#!/usr/bin/env python3
"""Typewriter-style streaming writer for human-facing CLI output.

Single responsibility: pace text to a TTY so results *unfold* like writing, with a
spinner over silent compute phases — while degrading to plain, instant output when
piped / in CI / disabled. It never changes WHAT is written, only the *cadence*, so
report artifacts (latest.json / latest.md) and any machine consumer reading stdout are
byte-for-byte unaffected.

Honest scope: scanner text is computed synchronously, so the typewriter is cosmetic
pacing of already-known text — not tokens arriving from a model. That is the right call
for a security tool: detection stays deterministic; only the cadence is animated.

Convention: results go to stdout (Streamer), transient progress to stderr (status).
"""
from __future__ import annotations

import itertools
import re
import sys
import threading
import time
from contextlib import contextmanager
from typing import Iterator, TextIO

from stayawake.utils import env

_WORD = re.compile(r"\S+\s*|\s+")   # a word + its trailing ws, or a run of ws (keeps newlines)


def _disabled_by_env() -> bool:
    return env.stream_disabled()


def _auto_enabled(out: TextIO) -> bool:
    """Animate only on a real TTY and only when not disabled by env."""
    if _disabled_by_env():
        return False
    try:
        return bool(out.isatty())
    except Exception:
        return False


def stream_enabled(out: TextIO | None = None, *, force_off: bool = False) -> bool:
    """One decision point for a caller: animate iff a TTY, not env-disabled, not forced off
    (e.g. a --no-stream flag). Callers pass this to both Streamer and status so the whole
    command animates or stays plain together — deterministic, and silent when stdout is
    captured (pipes, CI, tests)."""
    if force_off:
        return False
    return _auto_enabled(out or sys.stdout)


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


@contextmanager
def status(label: str, *, out: TextIO | None = None,
           enabled: bool | None = None, interval: float = 0.08) -> Iterator[None]:
    """Spinner covering a silent compute phase (FS walk, scanning a repo).

    Enabled → animate a spinner on `out` (default stderr) and wipe the line on exit, so the
    caller can print the result underneath. Disabled → SILENT (just yields): the result line
    that follows already conveys completion, so piped/CI output gets no redundant chatter."""
    out = out or sys.stderr
    on = _auto_enabled(out) if enabled is None else bool(enabled)
    if not on:
        yield
        return

    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    stop = threading.Event()

    def spin() -> None:
        for f in itertools.cycle(frames):
            if stop.is_set():
                break
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
