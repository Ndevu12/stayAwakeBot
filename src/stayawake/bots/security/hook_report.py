#!/usr/bin/env python3
"""How a git hook's report is written to the terminal."""
from __future__ import annotations

from stayawake.utils.render import LINK, SEVERITY, paint
from stayawake.utils.terminal import supports_color

BRAND = "StayAwakeBot"

_LEVELS = {"ok": SEVERITY["ok"], "warn": SEVERITY["warning"], "dim": SEVERITY["info"]}


def paint_at(text: str, level: str, stream) -> str:
    """Colour `text` at a shared level (ok, warn or dim) when the stream supports colour. Takes the
    text, the level and the stream. Returns the text to print."""
    return paint(text, _LEVELS.get(level), on=supports_color(stream))


def command(text: str, stream) -> str:
    """Render a runnable command in the shared command colour. Takes the command and the stream.
    Returns the text to print."""
    return paint(text, LINK, on=supports_color(stream))
