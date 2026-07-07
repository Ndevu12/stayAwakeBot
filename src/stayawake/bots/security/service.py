#!/usr/bin/env python3
"""Security orchestration: resolve targets → scan → deliver via sinks.

Single responsibility: wire the security stages together and hand the in-memory
`ScanReport` to a caller-selected list of output sinks. Detection lives in the matchers;
delivery lives in the sinks; this module performs NO output I/O of its own. Never executes
scanned code; remote repos are cloned read-only into sandboxes and removed after.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

from stayawake.core.config import load_yaml
from stayawake.core.io import resolve_reports_dir
from stayawake.core.streaming import Streamer, status, stream_enabled
from stayawake.core.timeutil import now_iso
from stayawake.core.adapters import github_api
from stayawake.core import auth
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.models import ScanResult, ScanReport
from stayawake.bots.security.sinks import (
    Sink, TerminalSink, JsonSink, SarifSink, FileSink, IssueSink, SlackSink)
from stayawake.bots.security.targets import ScanOptions, LocalRepoTarget, RemoteRepoTarget

REPORTS_DIR = Path("reports/security")
DEFAULT_CONFIG = "config/security.yml"
# Above this many targets, a terminal can't hold the whole report — if the user didn't
# already persist it (-d/--json), we drop the full Markdown+JSON in a temp dir and point there.
LARGE_FLEET = 25


def _read_config(config_path: str | None) -> dict:
    """Load the scan config. When `config_path` is None we use the default file if it
    exists, else an empty config — so a bare `saw scan` in any repo works without a
    config. An explicitly-given path that is missing is an error."""
    if config_path is None:
        p = Path(DEFAULT_CONFIG)
        return load_yaml(p) if p.exists() else {}
    return load_yaml(config_path)


def _enclosing_repo_root(start: Path | None = None) -> Path:
    """Nearest ancestor of `start` (default: CWD) that contains a .git, else `start`.
    Lets a bare invocation default to 'scan the repo I'm standing in', even from a
    subdirectory."""
    start = (start or Path.cwd()).resolve()
    for d in (start, *start.parents):
        if (d / ".git").exists():
            return d
    return start


# Project build-output dirs (not third-party node_modules) that the opt-in build-scan un-prunes.
_BUILD_OUTPUT_DIRS = {"dist", "build", "out", ".next"}


def _options(settings: dict, *, no_advisories: bool = False,
             external_audit: bool = False) -> ScanOptions:
    base = ScanOptions()
    exclude = set(settings.get("exclude_dirs", base.exclude_dirs))
    scan_build_outputs = bool(settings.get("scan_build_outputs", base.scan_build_outputs))
    if scan_build_outputs:
        exclude -= _BUILD_OUTPUT_DIRS          # let build outputs be traversed (matcher gates the rest)
    return ScanOptions(
        exclude_dirs=exclude,
        max_file_bytes=int(settings.get("max_file_bytes", base.max_file_bytes)),
        remote_clone_depth=int(settings.get("remote_clone_depth", base.remote_clone_depth)),
        scan_build_outputs=scan_build_outputs,
        # The offline CVE-advisory tier is ON by default; `--no-advisories` or config
        # `dependency_advisories: false` turns the section off.
        dependency_advisories=(not no_advisories) and bool(
            settings.get("dependency_advisories", base.dependency_advisories)),
        # External auditors are the one opt-in that leaves the offline sandbox (subprocess + a tool's
        # own network) — CLI flag OR config, off by default.
        external_audit=external_audit or bool(
            settings.get("external_audit", base.external_audit)),
    )


def discover_local_repos(patterns: list[str], opts: ScanOptions) -> list[Path]:
    repos: list[Path] = []
    seen: set[str] = set()
    for pat in patterns or []:
        root = Path(os.path.expanduser(pat).split("*", 1)[0] or "/")
        if not root.exists():
            root = root.parent
        if not root.exists():
            continue
        for dirpath, dirnames, _ in os.walk(root):
            if (Path(dirpath) / ".git").exists():
                rp = Path(dirpath).resolve()
                if str(rp) not in seen:
                    seen.add(str(rp))
                    repos.append(rp)
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in opts.exclude_dirs]
    return repos


def _remote_scope(cfg: dict, users, orgs, slugs) -> str:
    """A short label for the per-run line, describing WHICH remote repos a `--remote` run
    resolved (mirrors the ladder in `_resolve_remote`). Pure — no API calls."""
    if users or orgs or slugs:
        bits = []
        if users:
            bits.append("user " + ", ".join(users))
        if orgs:
            bits.append("org " + ", ".join(orgs))
        if slugs:
            bits.append(f"{len(slugs)} named repo(s)")
        return "; ".join(bits)
    gconf = cfg.get("targets", {}).get("github", {}) or {}
    if gconf.get("users") or gconf.get("orgs"):
        return "configured targets"
    return "your own repos"


def _resolve_remote(cfg: dict, opts: ScanOptions, *, users=None, orgs=None, slugs=None):
    """Resolve `--remote` targets to ('owner/name', ...). Ladder, first match wins (#1075):
      1. ad-hoc CLI selectors — `slugs` (named repos), `--user`/`--org` enumerations — which
         OVERRIDE config so you can target anything without editing a file;
      2. configured `targets.github.users/orgs`;
      3. infer "my repos" — the authenticated user's OWNED repos (private-inclusive via
         /user/repos), or a GitHub App installation's repos.
    Returns (sorted unique slugs, token, source)."""
    gconf = cfg.get("targets", {}).get("github", {}) or {}
    inc_forks = gconf.get("include_forks", False)
    inc_arch = gconf.get("include_archived", False)
    token, source = auth.resolve_token()
    resolved: list[str] = []

    if users or orgs or slugs:                       # 1. ad-hoc selectors override everything
        resolved += list(slugs or [])
        for u in users or []:
            resolved += github_api.list_repos(u, "users", token, inc_forks, inc_arch)
        for o in orgs or []:
            resolved += github_api.list_repos(o, "orgs", token, inc_forks, inc_arch)
    else:
        for kind in ("users", "orgs"):               # 2. configured targets
            for acct in gconf.get(kind, []) or []:
                resolved += github_api.list_repos(acct, kind, token, inc_forks, inc_arch)
        if not resolved and token:                   # 3. infer "my repos"
            resolved += (github_api.list_installation_repos(token, inc_arch)
                         if source == "github-app"
                         else github_api.list_my_repos(token, inc_forks, inc_arch))
    return sorted(set(resolved)), token, source


_SLUG_RE = re.compile(r"^[^/\s]+/[^/\s]+$")


def invalid_slugs(slugs) -> list[str]:
    """The entries that aren't a valid `owner/name` — so `--remote` positionals (which are
    slugs, not local paths) fail loudly instead of silently resolving to nothing."""
    return [s for s in (slugs or []) if not _SLUG_RE.match(s)]


# Shared actionable message when a `--remote` run resolves zero repositories.
REMOTE_EMPTY_HINT = (
    "No GitHub repositories resolved. Name targets with `--user U` / `--org O` / `owner/repo`, "
    "set `targets.github` in the config, or authenticate (`gh auth login` or GH_SECURITY_TOKEN) "
    "to act on your own repos.")


def _status_tag(r: ScanResult) -> str:
    """Bracketed, padded verdict tag for a per-target line (INFECTED / SUSPECT / clean)."""
    tag = ("INFECTED" if r.infected else "SUSPECT" if r.suspicious
           else "ERROR" if r.error else "clean")
    return f"[{tag:8}]"


def scan(config_path: str | None = None, *, remote: bool = False,
         paths: list[str] | None = None, users: list[str] | None = None,
         orgs: list[str] | None = None, slugs: list[str] | None = None,
         json_out: bool = False, sarif_path: str | Path | None = None,
         reports_dir: str | Path | None = None, alert: bool = False,
         no_stream: bool = False, pager: bool = False,
         no_advisories: bool = False, external_audit: bool = False) -> int:
    """Scan targets (READ-ONLY) and deliver the result through sinks. Scope is LOCAL by
    default — explicit `paths`, the configured local globs, or the current repo. With
    remote=True (`saw scan --remote`) it scans GitHub repos resolved by the #1075 ladder:
    ad-hoc `users`/`orgs`/`slugs` selectors → configured `targets.github` → your own repos.
    One scope per run. Persists NOTHING by default (terminal-first); files/alerts are opt-in.
    Remediation lives in `saw fix`, never here. Returns the verdict as an exit code: 1 if
    any target is INFECTED, else 0 — unconditionally (a CI gate just reads it)."""
    # Animate each stream by ITS OWN tty-ness (and not --no-stream / env-disabled). The
    # spinner + per-target dots live on STDERR, so they must key off stderr — otherwise a
    # `saw scan --json` (stdout piped to a tool, stderr still the user's terminal) would
    # lose its progress entirely. The human report lives on STDOUT and keys off stdout.
    progress_on = stream_enabled(sys.stderr, force_off=no_stream)
    report_on = stream_enabled(sys.stdout, force_off=no_stream)
    prog = Streamer(enabled=progress_on, out=sys.stderr)
    cfg = _read_config(config_path)
    settings = cfg.get("settings", {})
    opts = _options(settings, no_advisories=no_advisories, external_audit=external_audit)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])

    # --- WHAT to scan. LOCAL by default (explicit paths / configured globs / current repo);
    #     `--remote` switches scope to the configured GitHub targets. One scope per run.
    results: list[ScanResult] = []
    if remote:
        bad = invalid_slugs(slugs)
        if bad:
            print(f"error: --remote targets must be owner/repo slugs; got {bad}", file=sys.stderr)
            return 2
        resolved, token, source = _resolve_remote(cfg, opts, users=users, orgs=orgs, slugs=slugs)
        if not resolved:
            print(REMOTE_EMPTY_HINT, file=sys.stderr)
        else:
            print(f"Scanning {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'} "
                  f"({_remote_scope(cfg, users, orgs, slugs)}, via {source or 'anonymous'}).",
                  file=sys.stderr)
        m = len(resolved)
        for j, slug in enumerate(resolved, 1):
            rt = RemoteRepoTarget(slug, opts, token)
            try:
                with status(f"[{j}/{m}] cloning + scanning {slug}…", enabled=progress_on):
                    res = (scan_target(rt, sigs, allowlist) if rt.clone()
                           else ScanResult(target=slug, source="remote", error="clone failed"))
            finally:
                rt.cleanup()
            results.append(res)
            prog.line(f"  [{j}/{m}] {_status_tag(res)}  {res.target}  ({len(res.findings)} findings)")
    else:
        cfg_local = (cfg.get("targets", {}) or {}).get("local", []) or []
        if paths:                                  # explicit ad-hoc paths
            local_patterns = list(paths)
        elif cfg_local:                            # configured local globs
            local_patterns = list(cfg_local)
        else:                                      # bare run → scan the current repo
            local_patterns = [str(_enclosing_repo_root())]
            print(f"No targets configured; scanning current repository: {local_patterns[0]}",
                  file=sys.stderr)
        # Discovery (the FS walk) is itself slow and silent — cover it with a spinner.
        with status("Discovering repositories…", enabled=progress_on):
            repos = discover_local_repos(local_patterns, opts)
        if progress_on and repos:
            prog.line(f"Found {len(repos)} repositor{'y' if len(repos) == 1 else 'ies'} to scan.")
        n = len(repos)
        for i, repo in enumerate(repos, 1):
            display = str(repo).replace(os.path.expanduser("~"), "~")
            with status(f"[{i}/{n}] scanning {display}…", enabled=progress_on):  # spinner over real work
                with LocalRepoTarget(repo, display, opts) as t:
                    res = scan_target(t, sigs, allowlist)
            results.append(res)
            prog.line(f"  [{i}/{n}] {_status_tag(res)}  {res.target}  ({len(res.findings)} findings)")

    report = ScanReport(generated_at=now_iso(), results=results)

    # A large sweep can't fit a terminal's scrollback, and its per-finding evidence (hundreds
    # of lines) would bury the table. So for a big fleet the terminal shows the dashboard only
    # (table + collapsed clean) and the full per-finding detail moves to the written report.
    # Only meaningful for the human surface — `--json` carries everything to its consumer.
    large_fleet = not json_out and len(results) > LARGE_FLEET

    # --- compose the output sinks from the flags. Default is terminal-first and persists
    #     nothing; --json swaps the human report for machine JSON on stdout; --sarif / -d add
    #     redacted file artifacts; --alert pushes the durable GitHub-issue + Slack record.
    report_path: Path | None = None   # where the full report landed, for the pointer below
    sinks: list[Sink] = [
        JsonSink() if json_out
        else TerminalSink(enabled=report_on, pager=report_on and pager,
                          detail=not large_fleet)]
    if sarif_path:
        sinks.append(SarifSink(sarif_path))
    if reports_dir:
        rdir = resolve_reports_dir(reports_dir, settings_value=settings.get("reports_dir"),
                                   default=REPORTS_DIR, label="security reports")
        sinks.append(FileSink(rdir))
        report_path = Path(rdir) / "latest.md"
    if alert:
        sinks += [IssueSink(), SlackSink()]
    for sink in sinks:
        sink.emit(report)

    # Large sweep: guarantee the FULL report (with per-finding evidence) exists off-terminal
    # and point at it — the complete result is always recoverable. If the user already
    # persisted with -d we reuse that; otherwise drop the redacted Markdown+JSON in a temp dir.
    if large_fleet:
        if report_path is None:
            tmp = Path(tempfile.mkdtemp(prefix="sab-report-"))
            FileSink(tmp).emit(report)
            report_path = tmp / "latest.md"
        print(f"Full report ({len(results)} repos, with per-finding detail): {report_path}"
              "  (+ latest.json)", file=sys.stderr)

    # Verdict as exit code: INFECTED (confirmed findings) → 1, else 0. Unconditional —
    # the CI gate is just this exit code; SUSPICIOUS (heuristic-only) does not fail it.
    return 1 if report.any_infected else 0
