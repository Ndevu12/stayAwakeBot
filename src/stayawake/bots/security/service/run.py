#!/usr/bin/env python3
"""Scan orchestration: resolve targets → scan → deliver via sinks, and return the verdict
exit code. Wires the stages together and hands the in-memory `ScanReport` to a caller-selected
list of output sinks. Detection lives in the matchers; delivery lives in the sinks; config
decisions live in `config`; presentation cues live in `report`. This module performs NO output
I/O of its own. Never executes scanned code; remote repos are cloned read-only and removed after.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from stayawake.utils.io import resolve_reports_dir
from stayawake.utils.streaming import Streamer, status, stream_enabled
from stayawake.utils.timeutil import now_iso
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.models import ScanResult, ScanReport
from stayawake.bots.security.sinks import (
    Sink, TerminalSink, JsonSink, SarifSink, FileSink, IssueSink, SlackSink)
from stayawake.bots.security.targets import LocalRepoTarget, RemoteRepoTarget
# Target resolution lives in one shared module (resolution.py); imported under the names scan's
# body already uses (the `_`-prefixed ones stay for compat).
from stayawake.bots.security.resolution import (
    REMOTE_EMPTY_HINT, discover_local_repos, invalid_slugs,
    enclosing_repo_root as _enclosing_repo_root, remote_scope as _remote_scope,
    resolve_remote as _resolve_remote)
from stayawake.bots.security.service.config import (
    _read_config, _options, _as_bool, _require_db_or_error)
from stayawake.bots.security.service.report import _status_tag, _print_report_pointer


REPORTS_DIR = Path("reports/security")
# Above this many targets, a terminal can't hold the whole report — if the user didn't
# already persist it (-d/--json), we drop the full Markdown+JSON in a temp dir and point there.
LARGE_FLEET = 25
# #1203: independent of repo count, a report whose aggregate findings+advisories exceed this would
# overflow a terminal and be trimmed from scrollback (the user can't read the whole result). Above
# it — for ANY scan, local or remote — the terminal shows the dashboard only and the full per-finding
# detail moves to the written report. Catches the case the repo-count gate misses: FEW repos (even
# one), but a wall of findings. A cheap count off data the report already carries — no extra render.
MANY_FINDINGS = 200


def scan(config_path: str | None = None, *, remote: bool = False,
         paths: list[str] | None = None, users: list[str] | None = None,
         orgs: list[str] | None = None, slugs: list[str] | None = None,
         json_out: bool = False, sarif_path: str | Path | None = None,
         reports_dir: str | Path | None = None, alert: bool = False,
         no_stream: bool = False, pager: bool = False,
         no_advisories: bool = False, external_audit: bool = False,
         deep: bool = False, require_db: bool = False) -> int:
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
    opts = _options(settings, no_advisories=no_advisories, external_audit=external_audit, deep=deep)
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

    # A sweep too big for a terminal shows the SAME dashboard the large-fleet path already uses
    # (table + collapsed clean; per-finding detail OFF) and moves the full detail to the written
    # report. "Too big" is EITHER many repos (LARGE_FLEET) OR a large AGGREGATE of
    # findings+advisories (MANY_FINDINGS, #1203) — both apply to EVERY scan (local, org, account).
    # Cheap counts off data the report already carries; no extra render. `--json` carries everything.
    detail_units = sum(len(r.findings) + len(r.advisories) for r in results)
    spill = not json_out and (len(results) > LARGE_FLEET or detail_units > MANY_FINDINGS)

    # --- compose the output sinks from the flags. Default is terminal-first and persists
    #     nothing; --json swaps the human report for machine JSON on stdout; --sarif / -d add
    #     redacted file artifacts; --alert pushes the durable GitHub-issue + Slack record.
    report_path: Path | None = None   # where the full report landed, for the pointer below
    sinks: list[Sink] = [
        JsonSink() if json_out
        else TerminalSink(enabled=report_on, pager=report_on and pager,
                          detail=not spill)]          # spill → same board as large fleet
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

    # Spilled sweep: guarantee the FULL report exists off-terminal (same path large fleet already
    # used). Reuse -d when given; otherwise a temp dir. Highlight the path whenever a report was
    # written — local -d OR any spill — so it's never lost (#1203 UX).
    if spill and report_path is None:
        tmp = Path(tempfile.mkdtemp(prefix="sab-report-"))
        FileSink(tmp).emit(report)
        report_path = tmp / "latest.md"
    if report_path is not None:
        reason = (f"{len(results)} repositories scanned" if len(results) > LARGE_FLEET
                  else "the report is larger than a terminal can show")
        _print_report_pointer(report_path, spilled=spill, reason=reason)

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
