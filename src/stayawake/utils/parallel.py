#!/usr/bin/env python3
"""Ordered, error-isolated parallel execution over a work-list."""
from __future__ import annotations

import concurrent.futures as cf
import contextlib
import multiprocessing as mp
import os
from pathlib import Path
import queue
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

PROCESS = "process"
THREAD = "thread"



def _allowed_cpus() -> int:
    """How many CPUs this PROCESS may actually use — not how many the machine has.

    `os.cpu_count()` reports the host's cores even when the process is confined, so inside a
    two-CPU container on a large build host it reports the host and the pool oversubscribes by an
    order of magnitude. Each source below narrows to what is genuinely permitted: the scheduler's
    affinity mask, then a cgroup CPU quota. Nothing is hard-coded; on a machine with no confinement
    they all agree with the core count."""
    allowed = os.cpu_count() or 1
    for probe in (getattr(os, "process_cpu_count", None),
                  (lambda: len(os.sched_getaffinity(0))) if hasattr(os, "sched_getaffinity") else None):
        if probe is None:
            continue
        try:
            value = probe()
        except OSError:
            continue
        if value:
            allowed = min(allowed, value)
    quota = _cgroup_cpu_quota()
    return max(1, min(allowed, quota) if quota else allowed)


def _cgroup_cpu_quota() -> int | None:
    """Whole CPUs a cgroup CPU quota permits, or None when there is no quota to read."""
    v2 = Path("/sys/fs/cgroup/cpu.max")
    try:
        if v2.is_file():
            quota, _, period = v2.read_text().strip().partition(" ")
            if quota != "max" and period:
                return max(1, int(int(quota) / int(period)))
        v1_quota = Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        v1_period = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        if v1_quota.is_file() and v1_period.is_file():
            quota_us = int(v1_quota.read_text().strip())
            period_us = int(v1_period.read_text().strip())
            if quota_us > 0 and period_us > 0:
                return max(1, int(quota_us / period_us))
    except (OSError, ValueError):
        return None
    return None


def cpu_budget() -> int:
    """Workers an AUTO sweep may use: everything this process is allowed, minus one.

    The reserved CPU is what keeps the machine answering while a scan runs — the scanner reads
    hostile input, and a sweep that takes every core makes an unresponsive workstation
    indistinguishable from a scanner that hung. It is a subtraction rather than a fraction or a
    threshold so there is nothing to tune and no size of machine where the behaviour changes shape.
    An operator who wants every core still passes `-j`."""
    return max(1, _allowed_cpus() - 1)


def resolve_jobs(requested: int | None, count: int) -> int:
    """Worker count for a sweep of `count` items — the single policy every command shares.

    At most one worker per item (extra workers would idle), and ALWAYS 1 for a single item
    (the inline fast-path — no pool, no cost, behaviour unchanged). `requested=None` = AUTO →
    `min(cpu_count, count)`. An explicit `requested<=1` forces sequential."""
    if count <= 1:
        return 1
    if requested is None:
        return min(cpu_budget(), count)
    if requested <= 1:
        return 1
    return min(requested, count)

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


_WORKER_START_Q = None
_PARENT_CHECK_SECONDS = 0.5


@contextlib.contextmanager
def _ctrl_c_held():
    """Hold Ctrl-C off this thread while the block runs, and deliver it after."""
    if not hasattr(signal, "pthread_sigmask"):
        yield
        return
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


_SPAWN = mp.get_context("spawn")


class _WorkerProcess(_SPAWN.Process):
    """A worker process that starts with Ctrl-C held off."""

    def start(self) -> None:
        with _ctrl_c_held():
            super().start()


class _WorkerContext(type(_SPAWN)):
    """The spawn context, starting each worker with Ctrl-C held off."""

    Process = _WorkerProcess


def _worker_init(start_q, parent_pid: int | None = None) -> None:
    global _WORKER_START_Q
    _WORKER_START_Q = start_q
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    _leave_the_callers_streams()
    if parent_pid is not None:
        threading.Thread(target=_exit_when_the_parent_is_gone, args=(parent_pid,), daemon=True).start()


def _leave_the_callers_streams() -> None:
    """Point this worker's standard streams at the null device. Returns nothing."""
    try:
        null = os.open(os.devnull, os.O_RDWR)
    except OSError:
        return
    for fd in (0, 1, 2):
        try:
            os.dup2(null, fd)
        except OSError:
            pass
    os.close(null)


def _exit_when_the_parent_is_gone(parent_pid: int) -> None:
    """End this worker once the process that started it is gone. Takes that process's id."""
    while os.getppid() == parent_pid:
        time.sleep(_PARENT_CHECK_SECONDS)
    os._exit(1)


def _stop_signals_interrupt() -> Callable[[], None]:
    """Make SIGTERM and SIGHUP stop the run the way Ctrl-C does. Returns the function that puts the
    previous handlers back."""
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    previous = {}
    for name in ("SIGTERM", "SIGHUP"):
        number = getattr(signal, name, None)
        if number is not None and signal.getsignal(number) is signal.SIG_DFL:
            previous[number] = signal.signal(number, _interrupt)

    def restore() -> None:
        for number, handler in previous.items():
            signal.signal(number, handler)

    return restore


class StopRequested(KeyboardInterrupt):
    """A stop signal received while workers run. Holds the signal's number."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def _interrupt(signum, _frame) -> None:
    raise StopRequested(signum)


def _end_with(signum: int) -> None:
    """End this process with the stop signal it received. Takes the signal's number."""
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


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
    ctx = _WorkerContext()
    with _ctrl_c_held():
        start_q = ctx.Queue() if on_start else None
    ex = cf.ProcessPoolExecutor(max_workers=workers, mp_context=ctx,
                                initializer=_worker_init, initargs=(start_q, os.getpid()))
    interrupted = False
    restore_signals = _stop_signals_interrupt()
    try:
        return _pump(lambda i, item: ex.submit(_process_task, fn, i, item),
                     start_q, work, on_start, on_done)
    except KeyboardInterrupt as stopped:
        interrupted = True
        _terminate_pool(ex)                            # stop in-flight workers FIRST (shutdown nils _processes)
        ex.shutdown(wait=False, cancel_futures=True)   # then drop queued work, non-blocking
        if isinstance(stopped, StopRequested):
            restore_signals()
            _end_with(stopped.signum)
        raise
    finally:
        # Normal exit → wait=True reaps the (already-finished) workers promptly. Interrupt → wait=False
        # so we never re-block after terminating them.
        restore_signals()
        ex.shutdown(wait=not interrupted)
        if start_q is not None:
            start_q.close()
