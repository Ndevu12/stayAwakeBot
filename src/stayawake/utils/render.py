#!/usr/bin/env python3
"""Shareable terminal-rendering toolkit — the *mechanism* of readable terminal output
(colour, width, wrapping, rules), with the *format* left entirely to each caller.
"""
from __future__ import annotations

import shutil
import textwrap
from pathlib import Path
from typing import TextIO

from stayawake.utils import textsafe

RESET = "\033[0m"

SEVERITY: dict[str, str] = {
    "critical": "\033[1;31m",   # bold red
    "high": "\033[31m",         # red
    "medium": "\033[33m",       # yellow
    "low": "\033[33m",          # yellow
    "warning": "\033[1;31m",    # bold red — an audit warning is act-now
    "info": "\033[2m",          # dim — a review-worthy nudge
    "unknown": "\033[1;33m",    # bold yellow — the check could NOT be completed
    "ok": "\033[32m",           # green — no issue
}

MARKER: dict[str, str] = {
    # by severity — what the check actually established
    "ok": "✓",          # an established POSITIVE: installed, already guarded, scanned clean
    "warning": "⚠",     # act now
    "info": "•",        # a scoped negative ("none found HERE") or a nudge — never an all-clear
    "unknown": "?",     # the check could not be run or completed — not "fine", not "act now"
    # by role
    "fail": "✗",        # an operation failed, or a required thing is absent
    "detail": "→",      # a labelled follow-on line: "→ fix  ", "→ details: "
    "meta": "·",        # separator / dim metadata
}

STATUS: dict[str, str] = {
    "INFECTED": "\033[1;31m",   # bold red
    "SUSPECT": "\033[33m",      # yellow
    "ERROR": "\033[35m",        # magenta
    "clean": "\033[32m",        # green
}

LINK = "\033[1;36m"


def paint(text: str, code: str | None, *, on: bool) -> str:
    """Wrap `text` in ANSI `code` (reset after) iff `on` and a code is given — otherwise return
    `text` unchanged. The single place a colour escape is emitted, so gating is uniform and a
    caller that computed `on=False` (piped / NO_COLOR / CI) always gets clean text."""
    return f"{code}{text}{RESET}" if on and code else text


def path_link(path: Path | str, *, on: bool) -> str:
    """Render a filesystem path as coloured, clickable text when `on`.

    Uses OSC 8 `file://` hyperlinks (iTerm2, VS Code terminal, Windows Terminal, Ghostty, …) so a
    click / Cmd-click opens the file or folder in the OS without typing a command — the UX ask for
    operators who aren't comfortable with shell navigation. When `on` is False (piped /
    NO_COLOR / CI) return the plain path string — scripts and logs never see escape sequences.
    The visible text is still the full path, so copy-paste works even where hyperlinks don't.

    Safe for an UNTRUSTED path: the visible text is run through `textsafe.plain`, so a path
    that embeds control/escape (a nested OSC/CSI, a BEL) or bidi-override characters can't hijack the
    terminal or inject a workflow-command into a CI log — those become spaces. The OSC 8 target URI is
    built from the resolved path via `Path.as_uri()` (percent-encoded), so the click destination stays
    exact even after the visible text is sanitized. Today's callers pass a trusted report destination;
    this keeps the shared util safe by default for any future caller that doesn't."""
    p = Path(path)
    text = textsafe.plain(str(p), limit=4096)
    if not on:
        return text
    try:
        uri = p.resolve().as_uri()
    except OSError:
        return paint(text, LINK, on=True)                 # colour only if the URI can't be built
    # OSC 8: ESC ] 8 ; ; URI ST   coloured-text   ESC ] 8 ; ; ST
    return f"\033]8;;{uri}\033\\{paint(text, LINK, on=True)}\033]8;;\033\\"


def term_width(default: int = 80, *, stream: TextIO | None = None) -> int:
    """Best-effort terminal column count for width-aware wrapping. Falls back to `default`
    when there is no terminal (piped / captured / CI), so output is DETERMINISTIC off a real
    TTY — tests and pipes never depend on the window size. `stream` is accepted for symmetry
    with the colour gate but not required (shutil consults the process stdout/COLUMNS)."""
    try:
        cols = shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default
    return cols if cols and cols > 0 else default


def rule(width: int, char: str = "─") -> str:
    """A horizontal separator `width` columns wide (clamped to ≥0)."""
    return char * max(int(width), 0)


def wrap(text: str, width: int, *, indent: int = 0, hanging: int | None = None) -> list[str]:
    """Wrap PLAIN `text` to `width` columns and return the lines, with `indent` leading spaces
    on the first line and `hanging` (default = `indent`) on continuation lines.

    Colour must be applied to the RESULT, never to `text` — ANSI escapes have no display width
    and would corrupt the wrap maths. Long unbreakable tokens (paths, URLs) are NOT split, so a
    `~/.config/...` path is never chopped mid-token; such a line may exceed `width`, which is the
    right trade for a security tool (a mangled path is worse than an overlong line). A too-small
    `width` is floored so wrapping never raises or loops. Empty `text` yields no lines."""
    hanging = indent if hanging is None else hanging
    avail = max(int(width), indent + 8, hanging + 8, 8)
    return textwrap.wrap(
        text, width=avail,
        initial_indent=" " * indent, subsequent_indent=" " * hanging,
        break_long_words=False, break_on_hyphens=False,
    )


def block(text: str, *, indent: int = 0, width: int = 80, marker: str = "",
          code: str | None = None, color: bool = False) -> list[str]:
    """One wrapped paragraph: the first line is `indent` spaces + an optional coloured `marker`
    then the text; continuation lines align under the TEXT (a hanging indent), not the marker.
    Colour is applied AFTER wrapping — an ANSI escape has no display width, so the wrap/align maths
    must run on plain text first. Empty `text` yields no lines. This is the reusable unit both a
    labelled item ("→ fix  …") and a list entry ("• …" / "1. …") are built from."""
    hang = indent + len(marker)
    lines = wrap(text, width, indent=hang, hanging=hang)
    if not lines:
        return []
    lead = " " * indent + (paint(marker, code, on=color) if marker else "")
    lines[0] = lead + lines[0][hang:]
    return lines


def marked_list(items: list[str], *, ordered: bool = False, indent: int = 0, width: int = 80,
                start: int = 1, code: str | None = None, color: bool = False) -> list[str]:
    """Render `items` as a NUMBERED (`ordered=True` → "1. ", "2. " …, right-aligned so the dots
    line up past 9) or BULLETED (`• `) list — each item wrapped with a hanging indent so its
    continuations sit under the text, not the marker. The marker choice lives HERE, once, so a
    caller flips numbering ↔ bullets with one flag instead of re-implementing either style."""
    out: list[str] = []
    numw = len(str(start + len(items) - 1)) if items else 1
    for n, item in enumerate(items, start):
        marker = f"{str(n).rjust(numw)}. " if ordered else "• "
        out += block(item, indent=indent, width=width, marker=marker, code=code, color=color)
    return out
