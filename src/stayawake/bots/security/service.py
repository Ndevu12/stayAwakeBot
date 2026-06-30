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


def _options(settings: dict) -> ScanOptions:
    base = ScanOptions()
    return ScanOptions(
        exclude_dirs=set(settings.get("exclude_dirs", base.exclude_dirs)),
        max_file_bytes=int(settings.get("max_file_bytes", base.max_file_bytes)),
        remote_clone_depth=int(settings.get("remote_clone_depth", base.remote_clone_depth)),
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
         no_stream: bool = False) -> int:
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
    opts = _options(settings)
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

    # --- compose the output sinks from the flags. Default is terminal-first and persists
    #     nothing; --json swaps the human report for machine JSON on stdout; --sarif / -d add
    #     redacted file artifacts; --alert pushes the durable GitHub-issue + Slack record.
    sinks: list[Sink] = [JsonSink() if json_out else TerminalSink(enabled=report_on)]
    if sarif_path:
        sinks.append(SarifSink(sarif_path))
    if reports_dir:
        rdir = resolve_reports_dir(reports_dir, settings_value=settings.get("reports_dir"),
                                   default=REPORTS_DIR, label="security reports")
        sinks.append(FileSink(rdir))
    if alert:
        sinks += [IssueSink(), SlackSink()]
    for sink in sinks:
        sink.emit(report)

    # Verdict as exit code: INFECTED (confirmed findings) → 1, else 0. Unconditional —
    # the CI gate is just this exit code; SUSPICIOUS (heuristic-only) does not fail it.
    return 1 if report.any_infected else 0
