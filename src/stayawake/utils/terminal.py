#!/usr/bin/env python3
"""Terminal colour-capability detection — the single source of truth for "how much colour
may we emit?".
"""
from __future__ import annotations

import sys
from enum import IntEnum
from typing import TextIO

from stayawake.utils import env


class ColorLevel(IntEnum):
    """How much colour a stream supports. Ordered, so callers can compare (`>= ANSI256`)."""
    NONE = 0
    ANSI16 = 1
    ANSI256 = 2
    TRUECOLOR = 3


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
