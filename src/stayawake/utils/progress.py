#!/usr/bin/env python3
"""Concurrency-aware progress reporting for multi-target sweeps."""
from __future__ import annotations

import threading
import time
from typing import TextIO

from stayawake.utils import textsafe
from stayawake.utils.render import LINK, STATUS, paint, term_width

_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_MAX_INFLIGHT_LINES = 8


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
    def item_done(self, label: str, tag: str, detail: str, block: str | None = None) -> None: ...
    def finish(self) -> None: ...


def _header_line(done: int, total: int, tag: str, label: str, detail: str) -> str:
    """The one-line completion header shared by both reporters: `[done/total] tag label (detail)`.
    `(detail)` is omitted when empty, so a command that renders a full `block` below can pass a bare
    verdict header without a trailing `()`."""
    tail = f"  ({detail})" if detail else ""
    return f"  [{done}/{total}] {tag}  {label}{tail}"


class PlainProgress(ProgressReporter):
    """One completion entry per target — for pipes / CI / --no-stream. No cursor control, so it
    is safe to interleave with nothing (the sweep is the only writer via the main thread). When the
    caller supplies a `block` (its own fully-rendered per-repo result), it is printed right under the
    header — so a command renders its result AT completion, never in a separate untrackable pass."""

    def __init__(self, out: TextIO) -> None:
        self._out = out
        self._total = 0
        self._done = 0

    def start(self, total: int) -> None:
        self._total = total

    def item_done(self, label: str, tag: str, detail: str, block: str | None = None) -> None:
        self._done += 1
        safe = textsafe.plain(label, limit=200)
        text = _header_line(self._done, self._total, tag, safe, detail)
        if block:
            text += "\n" + block.rstrip("\n")
        self._out.write(text + "\n")
        self._out.flush()


class LiveProgress(ProgressReporter):
    """A multi-line live board on a TTY. All terminal writes happen on ONE render thread; the
    sweep only mutates state under a lock, so concurrent `item_*` calls never corrupt output."""

    def __init__(self, out: TextIO, *, color: bool, interval: float = 0.1,
                 verb: str = "Scanning") -> None:
        self._out = out
        self._color = color
        self._interval = interval
        self._verb = verb
        self._lock = threading.Lock()
        self._total = 0
        self._done = 0
        self._active: dict[str, None] = {}
        self._pending: list[str] = []
        self._spin = 0
        self._drawn = 0
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

    def item_done(self, label: str, tag: str, detail: str, block: str | None = None) -> None:
        with self._lock:
            self._active.pop(label, None)
            self._done += 1
            self._pending.append(self._completion_line(label, tag, detail, block))

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
        running = len(self._active)
        header = self._fit(f"{spin} {self._verb} {self._total} repos — "
                           f"{self._done} done · {running} running · {elapsed}s")
        lines = [paint(header, LINK, on=self._color)]
        shown = list(self._active)[:_MAX_INFLIGHT_LINES]
        for label in shown:
            lines.append(self._fit(f"  {spin} {textsafe.plain(label, limit=200)}…"))
        hidden = len(self._active) - len(shown)
        if hidden > 0:
            lines.append(f"  … +{hidden} more")
        return lines

    def _completion_line(self, label: str, tag: str, detail: str, block: str | None = None) -> str:
        safe = textsafe.plain(label, limit=200)
        line = self._fit(_header_line(self._done, self._total, tag, safe, detail))
        painted = paint(tag, _tag_color(tag), on=self._color)
        header = line.replace(tag, painted, 1) if self._color else line
        # A caller's own rendered result (guard's status block, …) scrolls up UNDER its header, as a
        # permanent region — not fitted (it's above the live region, so wrapping can't break the
        # cursor maths, and truncating a multi-line result would lose detail).
        return header + "\n" + block.rstrip("\n") if block else header

    def _fit(self, line: str) -> str:
        """Truncate a PLAIN line to the terminal width so the region never wraps (a wrapped
        region breaks the cursor maths). Caller paints AFTER fitting."""
        budget = max(term_width(stream=self._out) - 1, 8)
        if len(line) <= budget:
            return line
        return line[:budget - 1] + "…"


def make_progress(*, enabled: bool, out: TextIO, color: bool,
                  verb: str = "Scanning") -> ProgressReporter:
    """Pick the reporter for the run: a `LiveProgress` board when animation is `enabled`
    (a real TTY, not --no-stream / CI / piped), else a `PlainProgress` line-per-target. `verb`
    is the board header's action word ("Scanning"/"Fixing"/"Checking"…) — cosmetic only."""
    if enabled:
        return LiveProgress(out, color=color, verb=verb)
    return PlainProgress(out)
