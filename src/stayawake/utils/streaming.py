#!/usr/bin/env python3
"""Typewriter-style streaming writer for human-facing CLI output."""
from __future__ import annotations

import contextvars
import itertools
import re
import sys
import threading
import time
from contextlib import contextmanager
from typing import Iterator, TextIO

from stayawake.utils import env
from stayawake.utils.progress_events import current

_WORD = re.compile(r"\S+\s*|\s+")
_LIVE = contextvars.ContextVar("saw_live_output", default=False)


def ask_for_live_output(on: bool) -> None:
    """Remember whether this run asked for live output. Takes whether it did. Returns nothing."""
    _LIVE.set(bool(on))


def stream_enabled(out: TextIO | None = None, *, force_off: bool = False,
                   force_on: bool = False) -> bool:
    """Say whether this run shows live output. Takes the stream, and whether it was asked off or on.
    Returns False when it was asked off, which wins, including by the environment. Returns True when
    it was asked on, or when the stream is a terminal."""
    if force_off or env.stream_disabled():
        return False
    if force_on or _LIVE.get() or env.stream_forced():
        return True
    target = out or sys.stdout
    try:
        return bool(target.isatty())
    except Exception:
        return False


def _auto_enabled(out: TextIO) -> bool:
    """Say whether `out` shows live output on its own. Takes the stream. Returns the answer."""
    return stream_enabled(out)


class Streamer:
    """Writes text with a typewriter cadence (or instantly when disabled).

    cps:         characters/second target.
    max_seconds: hard cap on how long ONE write() may animate; long text speeds up to fit.
    by:          "word" (reads like writing, default) or "char".
    """

    def __init__(self, *, cps: float = 260.0, max_seconds: float = 1.2,
                 by: str = "word", out: TextIO | None = None,
                 enabled: bool | None = None) -> None:
        self.out = out or sys.stdout
        self.cps = max(float(cps), 1.0)
        self.max_seconds = max(float(max_seconds), 0.0)
        self.by = by if by in ("word", "char") else "word"
        self.enabled = _auto_enabled(self.out) if enabled is None else bool(enabled)

    def _chunks(self, text: str) -> list[str]:
        return list(text) if self.by == "char" else _WORD.findall(text)

    def write(self, text: str) -> None:
        if not text:
            return
        if not self.enabled:
            self.out.write(text)
            self.out.flush()
            return
        delay = 1.0 / self.cps
        total = len(text) * delay
        if self.max_seconds and total > self.max_seconds:
            delay *= self.max_seconds / total          # compress to the cap
        written = 0
        try:
            for chunk in self._chunks(text):
                self.out.write(chunk)
                self.out.flush()
                written += len(chunk)
                time.sleep(delay * len(chunk))
        except KeyboardInterrupt:
            self.out.write(text[written:])             # never leave a half-written line
            self.out.flush()
            raise

    def line(self, text: str = "") -> None:
        self.write(text + "\n")


_HOLDS = [0]
_HOLDS_LOCK = threading.Lock()
_SETTLE_SECONDS = 0.2


def _spinners_held() -> bool:
    """Tell whether a spinner must stay off the terminal. Returns True while something holds it."""
    with _HOLDS_LOCK:
        return _HOLDS[0] > 0


@contextmanager
def spinners_held(*, settle: float = _SETTLE_SECONDS, sleep=time.sleep) -> Iterator[None]:
    """Keep every running spinner off the terminal, its line cleared, while something else talks
    to the person at it. Takes how long to wait for a spinner to step aside, and the sleeper.
    Yields once they have."""
    with _HOLDS_LOCK:
        _HOLDS[0] += 1
    try:
        sleep(settle)
        yield
    finally:
        with _HOLDS_LOCK:
            _HOLDS[0] -= 1


@contextmanager
def status(label: str, *, out: TextIO | None = None,
           enabled: bool | None = None, interval: float = 0.08,
           index: int | None = None, of: int | None = None) -> Iterator[None]:
    """Spinner covering a silent compute phase (FS walk, scanning a repo).

    Enabled → animate a spinner on `out` (default stderr) and wipe the line on exit, so the
    caller can print the result underneath. Disabled → SILENT (just yields): the result line
    that follows already conveys completion, so piped/CI output gets no redundant chatter.
    When the run asked for progress events, write one step and do not draw the spinner.
    `index` and `of` say which step this is, when the caller knows."""
    events = current()
    if events.enabled:
        events.step(label, label, index=index, of=of)
        yield
        return
    out = out or sys.stderr
    on = _auto_enabled(out) if enabled is None else bool(enabled)
    if not on:
        yield
        return

    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    stop = threading.Event()

    def spin() -> None:
        cleared = False
        for f in itertools.cycle(frames):
            if stop.is_set():
                break
            if _spinners_held():
                if not cleared:
                    out.write("\r\033[K")
                    out.flush()
                    cleared = True
                time.sleep(interval)
                continue
            cleared = False
            out.write(f"\r\033[K{f} {label}")
            out.flush()
            time.sleep(interval)

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join(timeout=interval * 2)
        out.write("\r\033[K")                          # wipe the spinner line
        out.flush()


def say(text: str = "", *, no_stream: bool = False, out: TextIO | None = None) -> None:
    """Write a finished human report — typewriter on a TTY, instant when piped / --no-stream."""
    dest = out or sys.stdout
    Streamer(enabled=stream_enabled(dest, force_off=no_stream), out=dest).write(
        text if text.endswith("\n") else text + "\n")


def busy(label: str, *, no_stream: bool = False, out: TextIO | None = None):
    """Spinner over a silent compute phase, honoring `--no-stream` the same way `say` does."""
    dest = out or sys.stderr
    return status(label, out=dest, enabled=stream_enabled(dest, force_off=no_stream))
