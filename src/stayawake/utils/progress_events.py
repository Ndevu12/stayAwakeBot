#!/usr/bin/env python3
"""Progress a program can read: one JSON object per line on stderr."""
from __future__ import annotations

import json
import sys
import threading
from contextvars import ContextVar
from typing import Any, TextIO

from stayawake.utils import textsafe


def _strip_ellipsis(label: str) -> str:
    text = str(label).strip()
    if text.endswith("…"):
        return text[:-1].rstrip()
    if text.endswith("..."):
        return text[:-3].rstrip()
    return text


def step_id(label: str) -> str:
    """Name a step from the words a person sees. Takes the label. Returns the name, or `step` when
    the label has no words."""
    words: list[str] = []
    word: list[str] = []
    for ch in _strip_ellipsis(label).lower():
        if ch.isalnum():
            word.append(ch)
        elif word:
            words.append("".join(word))
            word = []
    if word:
        words.append("".join(word))
    return "-".join(words)[:80] or "step"


def _count(body: dict[str, Any], index: int | None, of: int | None) -> None:
    if isinstance(index, int) and not isinstance(index, bool) and index >= 0:
        body["index"] = index
    if isinstance(of, int) and not isinstance(of, bool) and of >= 0:
        body["of"] = of


class ErrorLines:
    """A stream that keeps lines reporting an error and drops the rest. Takes the stream the kept
    lines go to."""

    def __init__(self, out: TextIO) -> None:
        self.out = out
        self.pending = ""

    def write(self, text: str) -> int:
        self.pending += text
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            if line.lstrip().startswith("error:"):
                self.out.write(line + "\n")
                self.out.flush()
        return len(text)

    def flush(self) -> None:
        if self.pending.lstrip().startswith("error:"):
            self.out.write(self.pending if self.pending.endswith("\n") else self.pending + "\n")
            self.pending = ""
        self.out.flush()


class ProgressEvents:
    """One run's progress events. Silent when not enabled."""

    def __init__(self, command: str, *, enabled: bool, out: TextIO | None = None) -> None:
        self.command = command
        self.enabled = enabled
        self.out = out or sys.stderr
        self._lock = threading.Lock()
        self._started = False
        self._finished = False

    def start(self, steps: int | None = None) -> None:
        """Say the run began. Takes how many steps it will report, when that is known. Returns
        nothing. A second call is ignored."""
        if not self.enabled or self._started:
            return
        self._started = True
        body: dict[str, Any] = {"event": "start", "command": self.command}
        if isinstance(steps, int) and not isinstance(steps, bool) and steps >= 0:
            body["steps"] = steps
        self._emit(body)

    def step(self, step: str, label: str, *, index: int | None = None,
             of: int | None = None) -> None:
        """Say which step is underway. Takes its name, the words a person sees, and where it sits
        in the run when that is known. Returns nothing."""
        if not self.enabled:
            return
        shown = textsafe.plain(_strip_ellipsis(label), 200)
        if not shown:
            return
        body: dict[str, Any] = {"event": "step", "id": step_id(step), "label": shown}
        _count(body, index, of)
        self._emit(body)

    def target(self, path: str, *, index: int | None = None, of: int | None = None) -> None:
        """Say which repository or path is underway. Takes the path and where it sits in the run
        when that is known. Returns nothing."""
        if not self.enabled:
            return
        shown = textsafe.plain(path, 200)
        if not shown:
            return
        body: dict[str, Any] = {"event": "target", "path": shown}
        _count(body, index, of)
        self._emit(body)

    def done(self, code: int) -> None:
        """Say the run finished. Takes the status the command returns. Returns nothing. A second
        call is ignored. A run that never started still reports that it started."""
        if not self.enabled or self._finished:
            return
        if not self._started:
            self.start()
        self._finished = True
        self._emit({"event": "done", "exit": int(code)})

    def _emit(self, body: dict[str, Any]) -> None:
        line = json.dumps(body) + "\n"
        with self._lock:
            self.out.write(line)
            self.out.flush()


_CURRENT: ContextVar[ProgressEvents | None] = ContextVar("saw_progress_events", default=None)
_OFF = ProgressEvents("", enabled=False)


def current() -> ProgressEvents:
    """The progress events for this run. Returns a silent reporter when the run asked for none."""
    found = _CURRENT.get()
    return found if found is not None else _OFF


def covering(command: str, enabled: bool, fn, *, unfinished: int, out: TextIO | None = None):
    """Run `fn` while its progress events are published. Takes the command name, whether events are
    on, the call, the status to report when the call raises, and where the events are written.
    Returns what `fn` returns."""
    events = ProgressEvents(command=command, enabled=enabled, out=out)
    token = _CURRENT.set(events)
    code = unfinished
    try:
        code = fn()
        return code
    finally:
        try:
            events.done(code)
        finally:
            _CURRENT.reset(token)
