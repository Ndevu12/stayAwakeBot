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

from stayawake.utils import parallel
from stayawake.utils.io import resolve_reports_dir
from stayawake.utils.progress import make_progress
from stayawake.utils.streaming import Streamer, status, stream_enabled
from stayawake.utils.terminal import supports_color
from stayawake.utils.timeutil import now_iso
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.models import ScanResult, ScanReport
from stayawake.bots.security.sinks import (
    Sink, TerminalSink, JsonSink, SarifSink, FileSink, IssueSink, SlackSink)
# Target resolution lives in one shared module (resolution.py); imported under the names scan's
# body already uses (the `_`-prefixed ones stay for compat).
from stayawake.bots.security.resolution import (
    REMOTE_EMPTY_HINT, discover_local_repos, invalid_slugs,
    enclosing_repo_root as _enclosing_repo_root, remote_scope as _remote_scope,
    resolve_remote as _resolve_remote)
from stayawake.bots.security.service import workers as scan_workers
from stayawake.bots.security.service.config import (
    _read_config, _options, _as_bool, _require_db_or_error, jobs_setting as _jobs_setting)
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


def _resolve_workers(jobs: int | None, target_count: int) -> int:
    """Concurrency for THIS scope: at most one worker per target (extra workers would idle), and
    always 1 for a single target (the inline fast-path — no pool, no cost, behaviour unchanged).
    `jobs=None` = AUTO → min(cpu_count, targets). An explicit `jobs<=1` forces sequential."""
    if target_count <= 1:
        return 1
    if jobs is None:
        return min(os.cpu_count() or 1, target_count)
    if jobs <= 1:
        return 1
    return min(jobs, target_count)


def _scan_targets(jobs_batch: list, labels: list[str], sources: list[str], worker_fn, *,
                  workers: int, progress_on: bool) -> list[ScanResult]:
    """Scan a batch of targets, up to `workers` at a time, returning results in SUBMISSION order
    (so the persisted report is byte-identical whether run with one worker or many). A worker that
    crashes outright becomes an ERROR result (fail-closed → exit 2), never a silent drop. Any
    stdout/stderr a worker emitted is captured and REPLAYED here, after the live board closes, so a
    pool worker can never corrupt the board and no diagnostic is lost."""
    progress = make_progress(enabled=progress_on, out=sys.stderr,
                             color=supports_color(sys.stderr))
    progress.start(len(jobs_batch))

    def on_start(index: int, _item) -> None:
        progress.item_started(labels[index])

    def on_done(outcome: parallel.Outcome) -> None:
        if outcome.error:
            progress.item_done(labels[outcome.index], "[ERROR   ]", outcome.error)
        else:
            res = outcome.value.result
            progress.item_done(labels[outcome.index], _status_tag(res),
                               f"{len(res.findings)} findings")

    try:
        outcomes = parallel.run_ordered(worker_fn, jobs_batch, jobs=workers,
                                        backend=parallel.PROCESS,
                                        on_start=on_start, on_done=on_done)
    finally:
        progress.finish()

    results: list[ScanResult] = []
    diagnostics: list[str] = []
    for outcome in outcomes:
        if outcome.error:
            results.append(ScanResult(target=labels[outcome.index], source=sources[outcome.index],
                                      error=f"scan worker failed: {outcome.error}"))
        else:
            results.append(outcome.value.result)
            if outcome.value.diagnostics:
                diagnostics.append(outcome.value.diagnostics)
    for text in diagnostics:          # replay captured worker output AFTER the board is gone
        sys.stderr.write(text)
    return results


def scan(config_path: str | None = None, *, remote: bool = False,
         paths: list[str] | None = None, users: list[str] | None = None,
         orgs: list[str] | None = None, slugs: list[str] | None = None,
         json_out: bool = False, sarif_path: str | Path | None = None,
         reports_dir: str | Path | None = None, alert: bool = False,
         no_stream: bool = False, pager: bool = False,
         no_advisories: bool = False, external_audit: bool = False,
         deep: bool = False, require_db: bool = False, jobs: int | None = None) -> int:
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

    # How many targets to scan CONCURRENTLY. CLI `-j/--jobs` wins; else config `settings.jobs`;
    # else auto (resolved per-scope below against the target count). See `_resolve_workers`.
    jobs_pref = jobs if jobs is not None else _jobs_setting(settings)

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
        if resolved:
            jobs_batch = [scan_workers.RemoteScanJob(slug, opts, token, sigs, allowlist)
                          for slug in resolved]
            results = _scan_targets(jobs_batch, list(resolved), ["remote"] * len(resolved),
                                    scan_workers.scan_remote,
                                    workers=_resolve_workers(jobs_pref, len(resolved)),
                                    progress_on=progress_on)
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
        if repos:
            home = os.path.expanduser("~")
            labels = [str(repo).replace(home, "~") for repo in repos]
            jobs_batch = [scan_workers.LocalScanJob(str(repo), labels[i], opts, sigs, allowlist)
                          for i, repo in enumerate(repos)]
            results = _scan_targets(jobs_batch, labels, ["local"] * len(repos),
                                    scan_workers.scan_local,
                                    workers=_resolve_workers(jobs_pref, len(repos)),
                                    progress_on=progress_on)

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
