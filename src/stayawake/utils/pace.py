#!/usr/bin/env python3
"""How long a run expects to take, how far it has come, and when it must stop."""
from __future__ import annotations

import _thread
import math
import signal
import threading
from types import TracebackType

from stayawake.utils.progress_events import ProgressEvents

HEARTBEAT_SECONDS = 5.0
MINIMUM_BUDGET_SECONDS = 60
BUDGET_TIMES_ESTIMATE = 3
_START_SECONDS = 2.0
_FILES_PER_WORKER_SECOND = 250.0
_MEGABYTES_PER_WORKER_SECOND = 8.0
_COMMITS_PER_SECOND = 400.0


class DeadlineReached(KeyboardInterrupt):
    """The run reached the deadline it was given."""


def estimate_seconds(files: int, size: int, commits: int, workers: int) -> int:
    """Return how many seconds saw expects a target of this size to take on this machine. Takes its
    file count, its size in bytes, its commit count and the workers that will read it."""
    workers = max(1, workers)
    seconds = (_START_SECONDS + files / (_FILES_PER_WORKER_SECOND * workers)
               + size / 1e6 / (_MEGABYTES_PER_WORKER_SECOND * workers) + commits / _COMMITS_PER_SECOND)
    return math.ceil(seconds)


def budget_seconds(estimate: int) -> int:
    """Return how long a target with this estimate may take before saw considers something wrong."""
    return max(MINIMUM_BUDGET_SECONDS, BUDGET_TIMES_ESTIMATE * estimate)


class Pace:
    """One run's progress counts, its heartbeat, and its deadline."""

    def __init__(self, events: ProgressEvents, deadline: float | None = None) -> None:
        self.events = events
        self.deadline = deadline
        self.expired = False
        self._lock = threading.Lock()
        self._target = ""
        self._phase = ""
        self._done: int | None = None
        self._total = 0
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._previous_alarm = None

    def plan(self, target: str, *, files: int, size: int, commits: int, workers: int) -> None:
        """Say what a target holds and how long it should take. Takes the target and its work."""
        estimate = estimate_seconds(files, size, commits, workers)
        self.events.plan(target, files=files, size=size, commits=commits, workers=workers,
                         estimate_seconds=estimate, budget_seconds=budget_seconds(estimate))

    def begin(self, target: str, phase: str, total: int, *, counted: bool = True) -> None:
        """Start counting a phase of a target. Takes the target, the phase, its total, and whether
        its progress is counted as it goes."""
        with self._lock:
            self._target, self._phase, self._total = target, phase, total
            self._done = 0 if counted else None

    def advance(self, amount: int = 1) -> None:
        """Count `amount` more of the current phase as done."""
        with self._lock:
            if self._done is not None:
                self._done = min(self._total, self._done + amount)

    def beat(self) -> None:
        """Say how far the run has come."""
        with self._lock:
            target, phase, done, total = self._target, self._phase, self._done, self._total
        if phase:
            self.events.progress(target, phase=phase, done=done, total=total)

    def __enter__(self) -> "Pace":
        if self.events.enabled:
            self._threads.append(threading.Thread(target=self._heartbeat, daemon=True))
        if self.deadline is not None:
            self._arm_deadline(self.deadline)
        for thread in self._threads:
            thread.start()
        return self

    def __exit__(self, kind: type[BaseException] | None, value: BaseException | None,
                 trace: TracebackType | None) -> None:
        self._stop.set()
        self._disarm_deadline()
        if self.expired and kind is KeyboardInterrupt:
            raise DeadlineReached from None

    def _heartbeat(self) -> None:
        while not self._stop.wait(HEARTBEAT_SECONDS):
            self.beat()

    def _arm_deadline(self, seconds: float) -> None:
        if (hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
                and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)):
            self._previous_alarm = signal.signal(signal.SIGALRM, self._expire_now)
            signal.setitimer(signal.ITIMER_REAL, seconds)
            return
        self._threads.append(threading.Thread(target=self._expire_later, args=(seconds,), daemon=True))

    def _disarm_deadline(self) -> None:
        if self._previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self._previous_alarm)
            self._previous_alarm = None

    def _expire_now(self, _signum, _frame) -> None:
        self.expired = True
        raise DeadlineReached

    def _expire_later(self, seconds: float) -> None:
        if not self._stop.wait(seconds):
            self.expired = True
            _thread.interrupt_main()
