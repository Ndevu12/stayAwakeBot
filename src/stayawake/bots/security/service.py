#!/usr/bin/env python3
"""Security orchestration: resolve targets → scan → deliver via sinks.

Single responsibility: wire the security stages together and hand the in-memory
`ScanReport` to a caller-selected list of output sinks. Detection lives in the matchers;
delivery lives in the sinks; this module performs NO output I/O of its own. Never executes
scanned code; remote repos are cloned read-only into sandboxes and removed after.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from stayawake.core.config import load_yaml
from stayawake.core.io import resolve_reports_dir
from stayawake.core.streaming import Streamer, status, stream_enabled
from stayawake.core.timeutil import now_iso
# github_api/auth are consumed transitively through the resolution seam; kept imported so the
# targeting tests can patch them at the service boundary (`service.github_api`/`service.auth`) —
# they are the same module objects resolution.py uses, so the patches reach it.
from stayawake.core.adapters import github_api  # noqa: F401
from stayawake.core import auth  # noqa: F401
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.models import ScanResult, ScanReport
from stayawake.bots.security.sinks import (
    Sink, TerminalSink, JsonSink, SarifSink, FileSink, IssueSink, SlackSink)
from stayawake.bots.security.targets import ScanOptions, LocalRepoTarget, RemoteRepoTarget
# Target resolution lives in one shared module (resolution.py); re-imported here under the names
# service.scan's body and the targeting tests already use (the `_`-prefixed ones stay for compat).
from stayawake.bots.security.resolution import (
    DEFAULT_CONFIG, REMOTE_EMPTY_HINT, discover_local_repos, invalid_slugs,
    enclosing_repo_root as _enclosing_repo_root, remote_scope as _remote_scope,
    resolve_remote as _resolve_remote)

REPORTS_DIR = Path("reports/security")
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


# Project build-output dirs (not third-party node_modules) that the opt-in build-scan un-prunes.
_BUILD_OUTPUT_DIRS = {"dist", "build", "out", ".next"}


def _as_bool(value, default: bool) -> bool:
    """Coerce a config value to bool WITHOUT the string footgun — `bool("false")` is True, so a
    quoted YAML `external_audit: "false"` (or `"no"`/`"off"`/`"0"`) would otherwise read as True and
    silently ENABLE a security-sensitive option (external audit leaves the offline sandbox). A value
    that isn't a recognizable boolean falls back to `default`."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes", "on"):
            return True
        if s in ("false", "0", "no", "off", ""):
            return False
    return default


def _options(settings: dict, *, no_advisories: bool = False,
             external_audit: bool = False) -> ScanOptions:
    base = ScanOptions()
    exclude = set(settings.get("exclude_dirs", base.exclude_dirs))
    scan_build_outputs = _as_bool(settings.get("scan_build_outputs"), base.scan_build_outputs)
    if scan_build_outputs:
        exclude -= _BUILD_OUTPUT_DIRS          # let build outputs be traversed (matcher gates the rest)
    return ScanOptions(
        exclude_dirs=exclude,
        max_file_bytes=int(settings.get("max_file_bytes", base.max_file_bytes)),
        remote_clone_depth=int(settings.get("remote_clone_depth", base.remote_clone_depth)),
        scan_build_outputs=scan_build_outputs,
        # The offline CVE-advisory tier is ON by default; `--no-advisories` or config
        # `dependency_advisories: false` turns the section off.
        dependency_advisories=(not no_advisories) and _as_bool(
            settings.get("dependency_advisories"), base.dependency_advisories),
        # External auditors are the one opt-in that leaves the offline sandbox (subprocess + a tool's
        # own network) — CLI flag OR config, off by default. Strict bool coercion so a quoted
        # `"false"` can't silently enable it.
        external_audit=external_audit or _as_bool(
            settings.get("external_audit"), base.external_audit),
    )


def _require_db_or_error() -> int | None:
    """`--require-db` gate: a non-zero exit (with a stderr reason) if the advisory DB is absent or
    fails its content-hash integrity check; None if it's present and valid."""
    from stayawake.bots.security.dependencies import db
    st = db.cache_status()
    if not st.get("present"):
        print("saw scan --require-db: advisory DB not found — run `saw db update`.", file=sys.stderr)
        return 2
    if not st.get("schema_compatible", True):
        # Unusable (older format → scan falls back to the inline seed), but not tampering. Fail
        # closed for CI, with the honest reason so it's not mistaken for a security incident (#1137).
        print(f"saw scan --require-db: advisory DB is an older format (schema {st.get('schema')}) "
              "— run `saw db update`.", file=sys.stderr)
        return 2
    if not st.get("integrity_ok"):
        print("saw scan --require-db: advisory DB integrity check FAILED "
              f"({', '.join(st.get('mismatches', []))}) — run `saw db update`.", file=sys.stderr)
        return 2
    return None



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
         no_advisories: bool = False, external_audit: bool = False,
         require_db: bool = False) -> int:
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
    # A null/absent `allowlist` (the common `allowlist:` bare key, or no key) means "no
    # suppressions" → normalize to []. Only a genuinely wrong SHAPE is rejected below.
    allowlist = cfg.get("allowlist") or []
    # Fail CLOSED on a config we can't apply: an `allowlist` that isn't a list of mappings would
    # otherwise crash the per-target scan (caught as an ERROR with an empty, clean-looking result).
    # Reject it up front with a clear message rather than scanning under an unusable allowlist.
    if not (isinstance(allowlist, list) and all(isinstance(r, dict) for r in allowlist)):
        print("error: config `allowlist` must be a list of {signature, path_glob} mappings.",
              file=sys.stderr)
        return 2

    # Fail-closed gate (opt-in): a CI scan that must not silently lose malware coverage. Default is
    # fail-open — a missing/corrupt DB degrades to the always-shipped inline seed (never blind).
    if require_db or _as_bool(settings.get("require_db"), False):
        rc = _require_db_or_error()
        if rc is not None:
            return rc

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
        # Fail CLOSED when EXPLICIT targets (ad-hoc paths or configured globs) resolve to zero
        # repositories — a stale glob or a checkout with no `.git` scanned NOTHING, which must not
        # read as a clean pass. (A bare run has no explicit target, so it keeps its current-repo
        # fallback above and is unaffected.)
        if (paths or cfg_local) and not repos:
            print("error: the requested target(s) resolved to 0 repositories — nothing was "
                  "scanned; failing closed (not reporting 'clean').", file=sys.stderr)
            return 2
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

    # Verdict as exit code. INFECTED (confirmed findings) → 1. A target that ERRORED (could not be
    # scanned at all — an unreadable/malformed config, a read failure, a failed clone) carries no
    # verdict, so it must NEVER read as clean: fail CLOSED → 2. Otherwise clean → 0. Unconditional —
    # the CI gate is just this exit code; SUSPICIOUS (heuristic-only) does not fail it.
    if report.any_infected:
        return 1
    if report.any_error:
        errored = [r.target for r in results if r.error]
        print(f"error: {len(errored)} target(s) could not be scanned — failing closed (not "
              f"reporting 'clean'): {', '.join(errored)}", file=sys.stderr)
        return 2
    return 0
