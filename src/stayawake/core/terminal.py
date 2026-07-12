#!/usr/bin/env python3
"""Terminal colour-capability detection — the single source of truth for "how much colour
may we emit?".

A dependency-light leaf (stdlib + `core.env`) so any layer can import it without cycles: the
`saw` welcome banner and the security TerminalSink both ask this module, so the two never drift.

It answers with a `ColorLevel`, honouring the platform conventions a well-behaved CLI must
respect, in priority order:

  1. ``NO_COLOR`` (any non-empty value)  → NONE. A user's hard "no colour" preference wins
     over everything, per https://no-color.org.
  2. ``CLICOLOR_FORCE`` (truthy)         → force colour on even when the stream is not a TTY
     (e.g. recording the banner with ``vhs``, or ``saw | tee``). It does NOT override NO_COLOR.
  3. otherwise the stream must be a real TTY, and must not be a ``dumb`` terminal or a ``CI``
     run — piped / captured / scripted output stays clean text.
  4. the tier is then read from ``COLORTERM`` (truecolor) → ``TERM`` (…256…) → 16-colour.

Every env read goes through `core.env` (the one place the process environment is consulted),
so a test steers this by patching that single surface.
"""
from __future__ import annotations

import sys
from enum import IntEnum
from typing import TextIO

from stayawake.core import env


class ColorLevel(IntEnum):
    """How much colour a stream supports. Ordered, so callers can compare (`>= ANSI256`)."""
    NONE = 0        # plain text — no ANSI at all
    ANSI16 = 1      # the 8/16 base colours
    ANSI256 = 2     # 256-colour palette
    TRUECOLOR = 3   # 24-bit RGB


def _isatty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:                      # a stream with no / broken isatty → treat as not a TTY
        return False


def color_level(stream: TextIO | None = None) -> ColorLevel:
    """Resolve the colour capability of ``stream`` (default stdout). See the module docstring
    for the precedence rules."""
    stream = sys.stdout if stream is None else stream

    if env.no_color():                                 # user's hard preference wins over all
        return ColorLevel.NONE

    if not env.clicolor_force():                       # forced colour skips the TTY/CI/dumb gates
        if not _isatty(stream):
            return ColorLevel.NONE                     # piped / captured / redirected → clean text
        if (env.get(env.TERM) or "").lower() == "dumb":
            return ColorLevel.NONE
        if env.is_ci():
            return ColorLevel.NONE                     # CI logs are read as plain text

    # Capability tiers — read whatever TERM/COLORTERM the terminal (or a forcing caller) declares.
    if (env.get(env.COLORTERM) or "").lower() in ("truecolor", "24bit"):
        return ColorLevel.TRUECOLOR
    if "256" in (env.get(env.TERM) or "").lower():
        return ColorLevel.ANSI256
    return ColorLevel.ANSI16


def supports_color(stream: TextIO | None = None) -> bool:
    """Convenience boolean for callers that only need on/off (e.g. the report sink)."""
    return color_level(stream) is not ColorLevel.NONE
