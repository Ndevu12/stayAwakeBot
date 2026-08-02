#!/usr/bin/env python3
"""Ordered, error-isolated parallel execution over a work-list.

ONE shared seam for every multi-item sweep in the CLI (the scanner today; `fix`/`guard`/
`audit` per #1327). It maps a PURE, PICKLABLE function over items with a bounded worker
pool and guarantees the three properties every caller needs:

  * ORDER — `Outcome`s come back in SUBMISSION order regardless of completion order, so a
    persisted report is byte-identical whether run with one worker or many.
  * ISOLATION / FAIL-CLOSED — one item's exception, or a whole worker PROCESS dying
    (`BrokenProcessPool`), becomes that item's `Outcome.error`; it never aborts the sweep
    and never silently vanishes, so the caller can fail closed.
  * SINGLE-WRITER PROGRESS — `on_start` / `on_done` fire ONLY on the calling thread, so a
    progress display always has exactly one writer even though work runs concurrently.

Backends (the caller picks by workload — this is the whole point of one seam, two engines):
  * PROCESS — CPU-bound work (the scanner: `re` matching and the pure-Python char loops in
    the taint/obfuscation matchers hold the GIL, so threads would NOT parallelize it). Uses
    a `spawn` context for cross-platform determinism; the mapped fn and its args MUST be
    module-level and picklable (spawn re-imports the entry module).
  * THREAD — I/O-bound work (git writes / GitHub API calls release the GIL). No pickling.

`jobs <= 1` (or a single item) runs INLINE — no pool at all: zero startup cost, the
single-item fast path, and semantics identical to the pooled path. Stdlib only.
"""
from __future__ import annotations

import concurrent.futures as cf
import multiprocessing as mp
import os
import queue
from dataclasses import dataclass
from typing import Any, Callable, Iterable

PROCESS = "process"
THREAD = "thread"


def resolve_jobs(requested: int | None, count: int) -> int:
    """Worker count for a sweep of `count` items — the single policy every command shares.

    At most one worker per item (extra workers would idle), and ALWAYS 1 for a single item
    (the inline fast-path — no pool, no cost, behaviour unchanged). `requested=None` = AUTO →
    `min(cpu_count, count)`. An explicit `requested<=1` forces sequential."""
    if count <= 1:
        return 1
    if requested is None:
        return min(os.cpu_count() or 1, count)
    if requested <= 1:
        return 1
    return min(requested, count)

# How often the main loop wakes to drain start-signals while waiting on completions. Small
# enough that a live progress board feels responsive, large enough to add no real overhead.
_POLL_SECONDS = 0.05


@dataclass
class Outcome:
    """The result of running the mapped fn on ONE item.

    Exactly one of `value` / `error` is meaningful: `error` is a non-empty string (the
    formatted exception, or a dead-worker message) when the item failed, and `value` is the
    fn's return otherwise. `index` is the item's position in the input, so a caller can place
    results back in submission order."""
    index: int
    item: Any
    value: Any = None
    error: str | None = None


def run_ordered(fn: Callable[[Any], Any], items: Iterable[Any], *, jobs: int,
                backend: str = PROCESS,
                on_start: Callable[[int, Any], None] | None = None,
                on_done: Callable[[Outcome], None] | None = None) -> list[Outcome]:
    """Map `fn` over `items` with up to `jobs` workers, returning `Outcome`s in submission
    order. Never raises for a per-item failure (it becomes `Outcome.error`); a
    `KeyboardInterrupt` cancels outstanding work and propagates.

    `on_start(index, item)` fires as each item begins, `on_done(outcome)` as each completes —
    both ALWAYS on the calling thread, so a progress reporter is a single writer.
    """
    work = list(items)
    n = len(work)
    if n == 0:
        return []
    if jobs <= 1 or n == 1:
        return _run_inline(fn, work, on_start, on_done)
    workers = min(jobs, n)
    if backend == THREAD:
        return _run_threaded(fn, work, workers, on_start, on_done)
    if backend == PROCESS:
        return _run_process(fn, work, workers, on_start, on_done)
    raise ValueError(f"unknown backend {backend!r} (expected {PROCESS!r} or {THREAD!r})")


def _run_inline(fn, work, on_start, on_done) -> list[Outcome]:
    """Single item / jobs<=1: run in the calling thread, no executor. Identical semantics."""
    outcomes: list[Outcome] = []
    for i, item in enumerate(work):
        if on_start:
            on_start(i, item)
        outcome = _capture(fn, i, item)
        outcomes.append(outcome)
        if on_done:
            on_done(outcome)
    return outcomes


def _capture(fn, index, item) -> Outcome:
    """Run fn on one item, converting ANY exception into `Outcome.error` (fail-closed).
    KeyboardInterrupt is NOT swallowed — it must propagate to cancel the whole run."""
    try:
        return Outcome(index=index, item=item, value=fn(item))
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # noqa: BLE001 — one item must never abort the sweep
        return Outcome(index=index, item=item, error=f"{type(exc).__name__}: {exc}")


def _resolve(future, index, item) -> Outcome:
    """Turn a completed future into an Outcome. A dead worker surfaces here as
    `BrokenProcessPool` (an Exception) → recorded as an error, never a silent drop."""
    try:
        return Outcome(index=index, item=item, value=future.result())
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # noqa: BLE001
        return Outcome(index=index, item=item, error=f"{type(exc).__name__}: {exc}")


def _drain_starts(start_q, work, on_start, started: set) -> None:
    """Emit pending start-signals (main thread only), each index AT MOST ONCE (`started` dedups).
    Best-effort: a broken queue after a worker crash must not wedge the loop — completions still
    resolve via the futures."""
    if start_q is None or on_start is None:
        return
    while True:
        try:
            index = start_q.get_nowait()
        except queue.Empty:
            return
        except (OSError, ValueError, EOFError):
            return  # queue closed/broken (worker crash) — starts are cosmetic; keep going
        if 0 <= index < len(work) and index not in started:
            started.add(index)
            on_start(index, work[index])


def _pump(submit, start_q, work, on_start, on_done) -> list[Outcome]:
    """Shared completion loop for both pool backends: submit everything, then interleave draining
    start-signals with resolving completed futures — all on the calling thread.

    Contract: `on_start(i)` fires EXACTLY ONCE and always BEFORE `on_done(i)`. A fast item can
    complete before its start-signal (a separate channel — the mp.Queue) has been drained; without
    the guarantee below, `on_start` would arrive AFTER `on_done` and a progress reporter would show a
    finished item as still in-flight. So a completion forces the start first if it hasn't landed yet,
    and `started` suppresses the now-stale queued signal."""
    outcomes: list[Outcome | None] = [None] * len(work)
    started: set[int] = set()
    fut_index = {submit(i, item): i for i, item in enumerate(work)}
    pending = set(fut_index)
    while pending:
        _drain_starts(start_q, work, on_start, started)
        done, pending = cf.wait(pending, timeout=_POLL_SECONDS,
                                return_when=cf.FIRST_COMPLETED)
        for fut in done:
            i = fut_index[fut]
            if on_start is not None and i not in started:
                started.add(i)
                on_start(i, work[i])
            outcome = _resolve(fut, i, work[i])
            outcomes[i] = outcome
            if on_done:
                on_done(outcome)
    _drain_starts(start_q, work, on_start, started)  # flush any final starts
    return [o for o in outcomes if o is not None]


def _run_threaded(fn, work, workers, on_start, on_done) -> list[Outcome]:
    start_q: queue.Queue | None = queue.Queue() if on_start else None

    def task(index, item):
        if start_q is not None:
            start_q.put(index)
        return fn(item)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        try:
            return _pump(lambda i, item: ex.submit(task, i, item),
                         start_q, work, on_start, on_done)
        except KeyboardInterrupt:
            ex.shutdown(wait=False, cancel_futures=True)
            raise


# Set once per worker PROCESS by the pool initializer; the task wrapper reads it to post a
# start-signal. A module global (not a closure) because spawn requires picklable, importable
# callables.
_WORKER_START_Q = None


def _worker_init(start_q) -> None:
    global _WORKER_START_Q
    _WORKER_START_Q = start_q


def _process_task(fn, index, item):
    """Runs IN the worker process: post a start-signal (best-effort) then call the user fn.
    Kept tiny and dependency-free so the per-worker import cost stays low."""
    q = _WORKER_START_Q
    if q is not None:
        try:
            q.put(index)
        except Exception:  # noqa: BLE001 — a progress signal must never fail the actual work
            pass
    return fn(item)


def _terminate_pool(ex) -> None:
    """Hard-stop a process pool's workers NOW, for a Ctrl-C. `shutdown(cancel_futures=True)` only
    drops QUEUED futures — it neither interrupts a RUNNING worker nor prevents the executor's atexit
    hook from joining its manager thread with NO timeout at interpreter exit. Without this, a
    KeyboardInterrupt freezes the CLI for as long as the slowest in-flight scan (and can orphan
    workers when only the parent is signalled). Scans are read-only pure functions, so terminating
    mid-scan is safe — a remote worker may leave an ephemeral temp clone in the system temp dir,
    an acceptable cost on an interrupt."""
    # `_processes` is a dict while the pool is live but is niled by `shutdown()` — so callers MUST
    # terminate BEFORE shutting down; the `or {}` guards the shutdown-first / not-yet-spawned races.
    for proc in list((getattr(ex, "_processes", None) or {}).values()):
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001 — best-effort teardown; never mask the interrupt
            pass


def _run_process(fn, work, workers, on_start, on_done) -> list[Outcome]:
    ctx = mp.get_context("spawn")
    start_q = ctx.Queue() if on_start else None
    # Deliberately NOT a `with` block: ProcessPoolExecutor.__exit__ calls shutdown(wait=True), which
    # re-blocks on running workers on Ctrl-C. We own teardown so it can be non-blocking on interrupt.
    ex = cf.ProcessPoolExecutor(max_workers=workers, mp_context=ctx,
                                initializer=_worker_init, initargs=(start_q,))
    interrupted = False
    try:
        return _pump(lambda i, item: ex.submit(_process_task, fn, i, item),
                     start_q, work, on_start, on_done)
    except KeyboardInterrupt:
        interrupted = True
        _terminate_pool(ex)                            # stop in-flight workers FIRST (shutdown nils _processes)
        ex.shutdown(wait=False, cancel_futures=True)   # then drop queued work, non-blocking
        raise
    finally:
        # Normal exit → wait=True reaps the (already-finished) workers promptly. Interrupt → wait=False
        # so we never re-block after terminating them.
        ex.shutdown(wait=not interrupted)
        if start_q is not None:
            start_q.close()
