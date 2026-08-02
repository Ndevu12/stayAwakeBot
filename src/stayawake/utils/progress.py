#!/usr/bin/env python3
"""Concurrency-aware progress reporting for multi-target sweeps.

The scanner runs targets CONCURRENTLY (utils.parallel), so the old single-line `\\r` spinner
model — which assumes exactly one writer — no longer fits: several targets are in flight at
once. This module provides a small `ProgressReporter` that a sweep drives with SEMANTIC events
(`start` / `item_started` / `item_done` / `finish`), with two implementations:

  * `LiveProgress` — a multi-line LIVE region on a TTY: a header (`done/total · elapsed ·
    spinner`) plus one line per in-flight target, with each finished target printed as a
    permanent line that scrolls up out of the region (docker/cargo-style). A SINGLE dedicated
    render thread owns every terminal write, so concurrent completions can never interleave.
  * `PlainProgress` — one plain completion line per target (no cursor control). This is what a
    pipe / CI / `--no-stream` gets, matching the pre-parallel piped behaviour.

Convention (unchanged): progress goes to STDERR; the report goes to STDOUT. So `--json` and
redirected report output are byte-for-byte unaffected by whatever the board draws.
"""
from __future__ import annotations

import threading
import time
from typing import TextIO

from stayawake.utils import textsafe
from stayawake.utils.render import LINK, STATUS, paint, term_width

_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_MAX_INFLIGHT_LINES = 8   # cap the live region height; excess in-flight targets collapse to a tally


def _tag_color(tag: str) -> str | None:
    """Colour a verdict tag using scan's shared STATUS palette (so the board matches the sink).
    The tag arrives bracketed/padded (e.g. "[clean   ]"), so match by contained token."""
    for token, code in STATUS.items():
        if token in tag:
            return code
    return None


class ProgressReporter:
    """No-op base / interface. `start` opens the run, `item_started`/`item_done` bracket each
    target, `finish` closes it. Every method is safe to call from the sweep's main thread."""

    def start(self, total: int) -> None: ...
    def item_started(self, label: str) -> None: ...
    def item_done(self, label: str, tag: str, detail: str) -> None: ...
    def finish(self) -> None: ...


class PlainProgress(ProgressReporter):
    """One completion line per target — for pipes / CI / --no-stream. No cursor control, so it
    is safe to interleave with nothing (the sweep is the only writer via the main thread)."""

    def __init__(self, out: TextIO) -> None:
        self._out = out
        self._total = 0
        self._done = 0

    def start(self, total: int) -> None:
        self._total = total

    def item_done(self, label: str, tag: str, detail: str) -> None:
        self._done += 1
        safe = textsafe.plain(label, limit=200)
        self._out.write(f"  [{self._done}/{self._total}] {tag}  {safe}  ({detail})\n")
        self._out.flush()


class LiveProgress(ProgressReporter):
    """A multi-line live board on a TTY. All terminal writes happen on ONE render thread; the
    sweep only mutates state under a lock, so concurrent `item_*` calls never corrupt output."""

    def __init__(self, out: TextIO, *, color: bool, interval: float = 0.1) -> None:
        self._out = out
        self._color = color
        self._interval = interval
        self._lock = threading.Lock()
        self._total = 0
        self._done = 0
        self._active: dict[str, None] = {}     # insertion-ordered set of in-flight labels
        self._pending: list[str] = []          # permanent completion lines awaiting flush
        self._spin = 0
        self._drawn = 0                        # lines the live region currently occupies
        self._start_ts = 0.0
        self._running = False
        self._thread: threading.Thread | None = None

    # --- sweep-facing API (main thread; mutate state only) -------------------------------
    def start(self, total: int) -> None:
        self._total = total
        self._start_ts = time.monotonic()
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def item_started(self, label: str) -> None:
        with self._lock:
            self._active[label] = None

    def item_done(self, label: str, tag: str, detail: str) -> None:
        with self._lock:
            self._active.pop(label, None)
            self._done += 1
            self._pending.append(self._completion_line(label, tag, detail))

    def finish(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=self._interval * 4)
        # Bounded lock: if the render thread is wedged mid-write while holding the lock (a TTY paused
        # with Ctrl-S, a stuck terminal), skip the final erase rather than hang the main thread.
        if self._lock.acquire(timeout=1.0):
            try:
                self._render(final=True)  # flush completions, erase the live region
            finally:
                self._lock.release()

    # --- render thread (the SOLE terminal writer) ----------------------------------------
    def _loop(self) -> None:
        while self._running:
            with self._lock:
                self._render()
            time.sleep(self._interval)

    def _render(self, *, final: bool = False) -> None:
        parts: list[str] = []
        if self._drawn > 0:                   # move to the top of the current region and wipe it
            parts.append("\r")
            if self._drawn > 1:
                parts.append(f"\033[{self._drawn - 1}A")
            parts.append("\033[J")
        elif self._pending:
            parts.append("\r\033[J")
        parts.extend(line + "\n" for line in self._pending)
        self._pending.clear()
        region = [] if final else self._region()
        parts.append("\n".join(region))
        self._drawn = len(region)
        if parts:
            self._out.write("".join(parts))
            self._out.flush()

    # --- rendering helpers ---------------------------------------------------------------
    def _region(self) -> list[str]:
        elapsed = int(time.monotonic() - self._start_ts)
        spin = _FRAMES[self._spin % len(_FRAMES)]
        self._spin += 1
        # Show DONE and RUNNING distinctly: a bare "0/38" early in a sweep reads as stuck / as if it
        # were counting the wrong thing, when in fact several repos are already in flight.
        running = len(self._active)
        header = self._fit(f"{spin} Scanning {self._total} repos — "
                           f"{self._done} done · {running} running · {elapsed}s")
        lines = [paint(header, LINK, on=self._color)]
        shown = list(self._active)[:_MAX_INFLIGHT_LINES]
        for label in shown:
            lines.append(self._fit(f"  {spin} {textsafe.plain(label, limit=200)}…"))
        hidden = len(self._active) - len(shown)
        if hidden > 0:
            lines.append(f"  … +{hidden} more")
        return lines

    def _completion_line(self, label: str, tag: str, detail: str) -> str:
        safe = textsafe.plain(label, limit=200)
        # Fit the PLAIN line to width first, then colour the tag — so truncation never cuts an
        # ANSI reset (colour bleed) and the width maths counts visible characters, not bytes.
        line = self._fit(f"  [{self._done}/{self._total}] {tag}  {safe}  ({detail})")
        painted = paint(tag, _tag_color(tag), on=self._color)
        return line.replace(tag, painted, 1) if self._color else line

    def _fit(self, line: str) -> str:
        """Truncate a PLAIN line to the terminal width so the region never wraps (a wrapped
        region breaks the cursor maths). Caller paints AFTER fitting."""
        budget = max(term_width(stream=self._out) - 1, 8)
        if len(line) <= budget:
            return line
        return line[:budget - 1] + "…"


def make_progress(*, enabled: bool, out: TextIO, color: bool) -> ProgressReporter:
    """Pick the reporter for the run: a `LiveProgress` board when animation is `enabled`
    (a real TTY, not --no-stream / CI / piped), else a `PlainProgress` line-per-target."""
    if enabled:
        return LiveProgress(out, color=color)
    return PlainProgress(out)
