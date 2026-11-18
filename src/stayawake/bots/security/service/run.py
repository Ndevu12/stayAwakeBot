#!/usr/bin/env python3
"""Scan orchestration: resolve targets → scan → deliver via sinks, and return the verdict
exit code. Wires the stages together and hands the in-memory `ScanReport` to a caller-selected
list of output sinks. Detection lives in the matchers; delivery lives in the sinks; config
decisions live in `config`; presentation cues live in `report`. This module performs NO output
I/O of its own. Never executes scanned code; remote repos are cloned read-only and removed after.
"""
from __future__ import annotations

import os

from stayawake.utils.parallel import cpu_budget
from stayawake.utils import scratch
import sys
from pathlib import Path

import heapq

from stayawake.utils import parallel, pathsafe
from stayawake.utils.io import reports_dir_choice, resolve_reports_dir
from stayawake.utils import textsafe
from stayawake.utils.pace import DeadlineReached, Pace
from stayawake.utils.progress_events import current
from stayawake.utils.streaming import Streamer, status, stream_enabled
from stayawake.utils.sweep import run_sweep
from stayawake.utils.timeutil import now_iso
from stayawake.bots.security import scanner
from stayawake.bots.security.matchers import REGISTRY
from stayawake.bots.security.signatures import every_signature, load_signatures
from stayawake.bots.security.models import ScanResult, ScanReport
from stayawake.bots.security.sinks import (
    Sink, TerminalSink, JsonSink, SarifSink, FileSink, IssueSink, SlackSink)
# Target resolution lives in one shared module (resolution.py); imported under the names scan's
# body already uses (the `_`-prefixed ones stay for compat).
from stayawake.bots.security.resolution import (
    REMOTE_EMPTY_HINT, resolve_local_targets, invalid_slugs,
    bare_run_targets, remote_scope as _remote_scope,
    resolve_remote as _resolve_remote)
from stayawake.bots.security.service import workers as scan_workers
from stayawake.bots.security.service.config import (
    _read_config, _options, _as_bool, _require_db_or_error, jobs_setting as _jobs_setting)
from stayawake.bots.security.service.report import (
    _status_tag, _print_dependency_actions, _print_report_pointer)
from stayawake.lib.git.run import UNTRUSTED, one_pass, stdout as git_stdout


REPORTS_DIR = Path("reports/security")
LARGE_FLEET = 25
MANY_FINDINGS = 200


def _resolve_workers(jobs: int | None, target_count: int) -> int:
    """Concurrency for a multi-TARGET scope — the shared `parallel.resolve_jobs` policy (at most
    one worker per target, always 1 for a single target). Kept as a named alias so the call sites
    below read in scanner terms."""
    return parallel.resolve_jobs(jobs, target_count)


DEADLINE_REASON = "the scan reached its deadline before it finished this target"


def _scan_targets(jobs_batch: list, labels: list[str], sources: list[str], worker_fn, *,
                  workers: int, progress_on: bool, pace: Pace | None = None,
                  kept: dict[int, ScanResult] | None = None) -> list[ScanResult]:
    """Scan a batch of targets, up to `workers` at a time, returning results in SUBMISSION order
    (so the persisted report is byte-identical whether run with one worker or many). A worker that
    crashes outright becomes an ERROR result (fail-closed → exit 2), never a silent drop. Any
    stdout/stderr a worker emitted is captured and REPLAYED here, after the live board closes, so a
    pool worker can never corrupt the board and no diagnostic is lost."""
    outcomes = run_sweep(
        worker_fn, jobs_batch, jobs=workers, backend=parallel.PROCESS, labels=labels,
        describe=lambda o: (_status_tag(o.value.result), f"{len(o.value.result.findings)} findings"),
        progress_on=progress_on, out=sys.stderr,
        on_each=lambda o: _keep(o, kept, pace))

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


def _keep(outcome, kept: dict[int, ScanResult] | None, pace: Pace | None) -> None:
    """Remember a finished target's result and count it. Takes the outcome, where results are kept,
    and the run's pace."""
    if kept is not None and not outcome.error:
        kept[outcome.index] = outcome.value.result
    if pace is not None:
        pace.advance()


def _plan_target(pace: Pace | None, scope, display: str, files: list[str], workers: int) -> None:
    """Say what one local target holds. Takes the run's pace, the target, its files and workers."""
    if pace is None or not pace.events.enabled:
        return
    size = pathsafe.regular_size(Path(scope.root), files)
    commits = 0
    if scope.is_repo:
        counted = git_stdout(str(scope.root), ["rev-list", "--count", "--all"], context=UNTRUSTED).strip()
        commits = int(counted) if counted.isdigit() else 0
    pace.plan(display, files=len(files), size=size, commits=commits, workers=workers)


def _counting(pace: Pace | None, display: str, jobs: list):
    """Return the callback that counts a target's finished jobs: files while file chunks remain,
    then the whole-repository checks. Takes the run's pace, the target and its jobs."""
    chunks_left = sum(1 for job in jobs if job.include is not None)
    checks_total = len(jobs) - chunks_left
    checks_done = 0

    def on_done(outcome) -> None:
        nonlocal chunks_left, checks_done
        if pace is None:
            return
        job = jobs[outcome.index]
        if job.include is None:
            checks_done += 1
            if chunks_left == 0:
                pace.advance()
            return
        pace.advance(len(job.include))
        chunks_left -= 1
        if chunks_left == 0 and checks_total:
            pace.begin(display, "repository", checks_total)
            pace.advance(checks_done)

    return on_done


WITHIN_TARGET_MIN_FILES = 256
_CHUNKS_PER_WORKER = 4
_MIN_CHUNK_FILES = 16


def _file_workers(jobs_pref: int | None) -> int:
    """Worker count for parallelizing ONE target's files: AUTO (`None`) → the shared CPU budget,
    which leaves the machine a core and honours affinity/cgroup confinement; an explicit `-j N` caps
    it; `-j 1` → 1 (sequential, no pool). ONE authority — deriving it here as well is how the two
    paths came to disagree, with this one taking every core."""
    if jobs_pref is None:
        return cpu_budget()
    return max(1, jobs_pref)


def _balanced_chunks(root, files: list[str], nchunks: int) -> list[list[str]]:
    """Partition `files` into ~`nchunks` size-balanced groups (largest-file-first onto the lightest
    chunk — LPT), because per-file scan cost tracks file size (obfuscation is 68% of it). A few huge
    files can't pile onto one worker. Order within a chunk doesn't matter — matchers are per-file and
    the final sort is total."""
    sized = []
    for rel in files:
        try:
            size = (Path(root) / rel).stat().st_size
        except OSError:
            size = 0
        sized.append((size, rel))
    sized.sort(reverse=True)                      # LPT: place the biggest first
    heap = [(0, 0, i) for i in range(nchunks)]
    heapq.heapify(heap)
    buckets: list[list[str]] = [[] for _ in range(nchunks)]
    for size, rel in sized:
        load, count, idx = heapq.heappop(heap)
        buckets[idx].append(rel)
        heapq.heappush(heap, (load + size, count + 1, idx))
    return [b for b in buckets if b]              # drop any empty bucket


def _scan_one_target(scope, display: str, opts, sigs, allowlist, workers: int,
                     progress_on: bool, settings: dict, pace: Pace | None = None) -> ScanResult:
    """Scan ONE local target. Above the file-count floor and with >1 worker, split its files into
    size-balanced chunks scanned in parallel (partitionable matchers) alongside the whole-target
    matchers (each once), then MERGE raw findings through `scanner.finalize` — byte-identical to a
    sequential scan. Below the floor / 1 worker, scan sequentially (no pool overhead)."""
    try:
        with one_pass():
            return _scan_one_target_inner(scope, display, opts, sigs, allowlist, workers,
                                          progress_on, settings, pace)
    except Exception as exc:  # never let one target crash the CLI — fail CLOSED (mirrors scan_target)
        return ScanResult(target=display, source="local",
                          error=f"scan worker failed: {type(exc).__name__}: {exc}")


def _scan_one_target_inner(scope, display: str, opts, sigs, allowlist, workers: int,
                           progress_on: bool, settings: dict, pace: Pace | None = None) -> ScanResult:
    reader = scan_workers.read_as(scope, display, opts, include_only=scope.include_only)
    files = list(reader.iter_files())
    min_files = int(settings.get("parallel_min_files", WITHIN_TARGET_MIN_FILES) or 0)
    sequential = workers <= 1 or len(files) < min_files or scope.names_one_file
    _plan_target(pace, scope, display, files, 1 if sequential else workers)
    if pace is not None:
        pace.begin(display, "files", len(files), counted=not sequential)
    if sequential:
        worker_scan = scan_workers.scan_local(
            scan_workers.LocalScanJob(scope, display, opts, sigs, allowlist))
        if worker_scan.diagnostics:
            sys.stderr.write(worker_scan.diagnostics)
        return worker_scan.result

    # One authority for what may run over this target: this branch used to read `sigs` directly,
    # so every scoping rule applied to the sequential path only, and a `-j 4` run answered about
    # the enclosing repository where `-j 1` did not.
    scoped = scan_workers.matchers_for_target(sigs, scope)
    all_sigs = every_signature(sigs)
    order = list(scoped.keys())
    part_names = tuple(n for n in order if n in REGISTRY and REGISTRY[n].partitionable)
    whole_names = [n for n in order if n in REGISTRY and not REGISTRY[n].partitionable]
    nchunks = max(1, min(workers * _CHUNKS_PER_WORKER, -(-len(files) // _MIN_CHUNK_FILES)))
    chunks = _balanced_chunks(scope.root, files, nchunks)
    jobs = [scan_workers.MatcherJob(scope, display, opts, part_names, tuple(chunk), scoped, all_sigs)
            for chunk in chunks]
    jobs += [scan_workers.MatcherJob(scope, display, opts, (name,), None, scoped, all_sigs)
             for name in whole_names]

    with status(f"Scanning {display} — {len(files)} files across {workers} workers…",
                enabled=progress_on):
        outcomes = parallel.run_ordered(scan_workers.collect_partial, jobs, jobs=workers,
                                        backend=parallel.PROCESS, on_done=_counting(pace, display, jobs))

    merged: dict[str, list] = {}
    read_errors: list[str] = []
    coverage_notes: list[str] = []
    diagnostics: list[str] = []
    worker_error: str | None = None
    for outcome in outcomes:
        if outcome.error:                        # a chunk/matcher worker died → the target is only
            worker_error = outcome.error
            continue
        partial = outcome.value
        for name, found in partial.by_matcher.items():
            merged.setdefault(name, []).extend(found)
        read_errors.extend(partial.read_errors)
        coverage_notes.extend(partial.coverage_notes)
        if partial.diagnostics:
            diagnostics.append(partial.diagnostics)
    for text in diagnostics:                     # replay captured worker output after the spinner
        sys.stderr.write(text)
    if worker_error is not None:
        return ScanResult(target=display, source="local", error=f"scan worker failed: {worker_error}")
    result = scanner.finalize(display, "local", merged, order, read_errors, coverage_notes,
                              opts, scope.scan_root, allowlist, all_sigs, scope.is_repo)
    # The other local path — one small target, and every target of a fleet scan — goes through
    # `workers.scan_local`, which attaches this itself. This branch is the one it does not reach.
    if scope.is_repo:
        if pace is not None:
            pace.begin(display, "history", 0, counted=False)
        scanner.attach_history_note(result, str(scope.root), opts, sigs, allowlist)
    if not scope.is_repo and not files and not result.findings:
        result.error = scan_workers.NOTHING_TO_READ
    elif not result.error:
        result.error = scan_workers.unsure_reason(scope, sigs)
    result.notes.extend(scan_workers.notes_for(scope, set(reader.pruned_dirs)))
    return result


def _why_nothing_at(pattern: str) -> str:
    """Say why a requested path gave nothing to scan. Takes the path or pattern as given. Returns
    the reason, naming the path."""
    shown = textsafe.plain(pattern, limit=4096)
    if any(mark in pattern for mark in "*?["):
        return f"{shown} matched nothing"
    folder = Path(os.path.expanduser(pattern)).parent
    while not os.path.lexists(folder) and folder != folder.parent:
        folder = folder.parent
    if os.path.lexists(folder) and not os.access(folder, os.X_OK):
        return f"{shown} is inside {textsafe.plain(str(folder), limit=4096)}, which this account cannot open"
    return f"{shown} does not exist"


def _results_at_deadline(planned: dict[str, list[str]], kept: dict[int, ScanResult],
                         paths: list[str] | None) -> list[ScanResult]:
    """Return each planned target's result, with the ones the deadline cut short reported as not
    scanned. Takes the planned targets, the results kept so far, and the paths asked for."""
    labels, sources = planned["labels"], planned["sources"]
    if not labels:
        named = ", ".join(paths or []) or "the scan"
        return [ScanResult(target=named, source="local",
                           error="the scan reached its deadline before it found its targets")]
    return [kept.get(index) or ScanResult(target=label, source=source, error=DEADLINE_REASON)
            for index, (label, source) in enumerate(zip(labels, sources))]


def scan(config_path: str | None = None, *, remote: bool = False,
         paths: list[str] | None = None, users: list[str] | None = None,
         orgs: list[str] | None = None, slugs: list[str] | None = None,
         json_out: bool = False, sarif_path: str | Path | None = None,
         reports_dir: str | Path | None = None, alert: bool = False,
         no_stream: bool = False, pager: bool = False,
         no_advisories: bool = False, external_audit: bool = False,
         deep: bool = False, history: bool = False, require_db: bool = False,
         jobs: int | None = None, deadline: float | None = None) -> int:
    """Scan targets (READ-ONLY) and deliver the result through sinks. Scope is LOCAL by
    default — explicit `paths`, the configured local globs, or the current repo. With
    remote=True (`saw scan --remote`) it scans GitHub repos resolved by the ladder:
    ad-hoc `users`/`orgs`/`slugs` selectors → configured `targets.github` → your own repos.
    One scope per run. Persists NOTHING by default (terminal-first); files/alerts are opt-in.
    Remediation lives in `saw fix`, never here. Returns the verdict as an exit code: 1 if
    any target is INFECTED, else 0 — unconditionally (a CI gate just reads it)."""
    events = current()
    events.start()
    progress_on = stream_enabled(sys.stderr, force_off=no_stream) and not events.enabled
    report_on = stream_enabled(sys.stdout, force_off=no_stream)
    prog = Streamer(enabled=progress_on, out=sys.stderr)
    cfg = _read_config(config_path, targets=paths)
    if cfg is None:
        return 2
    settings = cfg.get("settings", {})
    opts = _options(settings, no_advisories=no_advisories, external_audit=external_audit,
                    deep=deep, history=history)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist") or []

    if require_db or _as_bool(settings.get("require_db"), False):
        rc = _require_db_or_error()
        if rc is not None:
            return rc

    jobs_pref = jobs if jobs is not None else _jobs_setting(settings)

    results: list[ScanResult] = []
    pace = Pace(events, deadline)
    kept: dict[int, ScanResult] = {}
    planned: dict[str, list[str]] = {"labels": [], "sources": []}
    with pace:
        try:
            if remote:
                bad = invalid_slugs(slugs)
                if bad:
                    print(f"error: --remote targets must be owner/repo slugs; got {bad}", file=sys.stderr)
                    return 2
                resolved, token, source = _resolve_remote(cfg, opts, users=users, orgs=orgs, slugs=slugs)
                if not resolved:
                    print(REMOTE_EMPTY_HINT, file=sys.stderr)
                elif not events.enabled:
                    print(f"Scanning {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'} "
                          f"({_remote_scope(cfg, users, orgs, slugs)}, via {source or 'anonymous'}).",
                          file=sys.stderr)
                if resolved:
                    jobs_batch = [scan_workers.RemoteScanJob(slug, opts, token, sigs, allowlist)
                                  for slug in resolved]
                    planned.update(labels=list(resolved), sources=["remote"] * len(resolved))
                    pace.begin("", "targets", len(resolved))
                    results = _scan_targets(jobs_batch, list(resolved), ["remote"] * len(resolved),
                                            scan_workers.scan_remote,
                                            workers=_resolve_workers(jobs_pref, len(resolved)),
                                            progress_on=progress_on, pace=pace, kept=kept)
            else:
                cfg_local = (cfg.get("targets", {}) or {}).get("local", []) or []
                if paths:
                    local_patterns = list(paths)
                else:
                    local_patterns = bare_run_targets(cfg_local)
                    if not cfg_local:
                        print("No target named: scanning your home folder. "
                              "`saw scan .` scans only the folder you are in.", file=sys.stderr)
                unsearched: list[Path] = []
                with status("Discovering targets…", enabled=progress_on):
                    found = resolve_local_targets(local_patterns, opts, unsearched=unsearched)
                repos = [t.root for t in found]
                if not repos:
                    for pattern in local_patterns:
                        print(f"error: {_why_nothing_at(pattern)}.", file=sys.stderr)
                    print("Nothing was scanned.", file=sys.stderr)
                    return 2
                if progress_on and repos:
                    prog.line(f"Found {len(repos)} repositor{'y' if len(repos) == 1 else 'ies'} to scan.")
                if unsearched and (progress_on or events.enabled):
                    unread = (f"{len(unsearched)} folder{'' if len(unsearched) == 1 else 's'} could not be "
                              "read, so the scan is not complete. Check their permissions and scan again.")
                    if events.enabled:
                        print(unread, file=sys.stderr)
                    else:
                        prog.line(unread)
                if len(repos) == 1:
                    home = os.path.expanduser("~")
                    display = str(found[0].label).replace(home, "~")
                    events.target(str(found[0].root), index=1, of=1)
                    planned.update(labels=[display], sources=["local"])
                    results = [_scan_one_target(found[0], display, opts, sigs, allowlist,
                                                _file_workers(jobs_pref), progress_on, settings, pace)]
                elif repos:
                    home = os.path.expanduser("~")
                    labels = [str(t.label).replace(home, "~") for t in found]
                    jobs_batch = [scan_workers.LocalScanJob(t, labels[i], opts, sigs, allowlist)
                                  for i, t in enumerate(found)]
                    planned.update(labels=labels, sources=["local"] * len(repos))
                    pace.begin("", "targets", len(repos))
                    results = _scan_targets(jobs_batch, labels, ["local"] * len(repos),
                                            scan_workers.scan_local,
                                            workers=_resolve_workers(jobs_pref, len(repos)),
                                            progress_on=progress_on, pace=pace, kept=kept)
        except KeyboardInterrupt:
            if not pace.expired:
                raise
            results = _results_at_deadline(planned, kept, paths)

    report = ScanReport(generated_at=now_iso(), results=results)

    detail_units = sum(len(r.findings) + len(r.advisories) for r in results)
    spill = not json_out and (len(results) > LARGE_FLEET or detail_units > MANY_FINDINGS)

    report_path: Path | None = None
    sinks: list[Sink] = [
        JsonSink() if json_out
        else TerminalSink(enabled=report_on, pager=report_on and pager,
                          detail=not spill)]
    if sarif_path:
        sinks.append(SarifSink(sarif_path))
    settings_reports_dir = settings.get("reports_dir")
    if reports_dir_choice(reports_dir, settings_value=settings_reports_dir):
        rdir = resolve_reports_dir(reports_dir, settings_value=settings_reports_dir,
                                   default=REPORTS_DIR, label="security reports")
        sinks.append(FileSink(rdir))
        report_path = Path(rdir) / "latest.md"
    if alert:
        sinks += [IssueSink(), SlackSink()]
    for sink in sinks:
        sink.emit(report)

    if spill and report_path is None:
        tmp = scratch.kept_dir("the full report")
        FileSink(tmp).emit(report)
        report_path = tmp / "latest.md"
    if report_path is not None and not events.enabled:
        reason = f"{len(results)} repositories" if len(results) > LARGE_FLEET else ""
        _print_report_pointer(report_path, spilled=spill, reason=reason)
    if not events.enabled:
        _print_dependency_actions(results)

    if report.any_infected:
        return 1
    if report.any_error:
        errored = [r for r in results if r.error]
        print(f"error: {len(errored)} target(s) could not be scanned, so they are not clean:",
              file=sys.stderr)
        for r in errored:
            print(f"  {textsafe.plain(r.target)} — {textsafe.plain(r.error)}", file=sys.stderr)
        return 2
    return 0
