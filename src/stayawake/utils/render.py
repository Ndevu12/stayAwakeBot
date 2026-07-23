#!/usr/bin/env python3
"""Shareable terminal-rendering toolkit — the *mechanism* of readable terminal output
(colour, width, wrapping, rules), with the *format* left entirely to each caller.

Why this exists: two surfaces render human reports — the security scan
(`bots/security/sinks/render.py`) and the local-hygiene audit
(`bots/security/hygiene`). They present DIFFERENT data (repo findings with a path/signature/
evidence vs. host issues with a title/detail/fix + an incident banner), so they must own
their own *layout*. But they were re-implementing the same *machinery*: ANSI colour with a
severity palette, TTY-gating, alignment, wrapping. This module holds that machinery ONCE so
the two never drift on "what colour is critical?" or "how do we wrap a long line?", while each
caller stays free to compose its own shape.

Design: a small kit of pure functions, no I/O and no environment reads (a dependency-light
leaf, like `core.terminal`). Colour is applied by `paint()` only when the caller passes
`on=True` — the caller decides on/off once via `core.terminal.supports_color(stream)`, so the
gating policy (NO_COLOR / CLICOLOR_FORCE / TTY / CI) lives in that one place and this stays a
pure formatter. Escapes have no display width, so every width calculation is done on PLAIN
text and colour is applied AFTER — callers must wrap/pad first, then paint.
"""
from __future__ import annotations

import shutil
import textwrap
from pathlib import Path
from typing import TextIO

RESET = "\033[0m"

# The ONE colour vocabulary the whole CLI shares. Callers reference a level by name; the ANSI
# codes live here once. Severity levels span both surfaces: the scanner grades
# critical/high/medium/low; the audit grades warning/info; `ok` is the green "all clear".
SEVERITY: dict[str, str] = {
    "critical": "\033[1;31m",   # bold red
    "high": "\033[31m",         # red
    "medium": "\033[33m",       # yellow
    "low": "\033[33m",          # yellow
    "warning": "\033[1;31m",    # bold red — an audit warning is act-now
    "info": "\033[2m",          # dim — a review-worthy nudge
    "ok": "\033[32m",           # green — no issue
}

# Scan's per-target status tokens (distinct from severity: a verdict, not a level).
STATUS: dict[str, str] = {
    "INFECTED": "\033[1;31m",   # bold red
    "SUSPECT": "\033[33m",      # yellow
    "ERROR": "\033[35m",        # magenta
    "clean": "\033[32m",        # green
}

# Clickable path convention — bold cyan reads as a link in most terminals.
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
    operators who aren't comfortable with shell navigation (#1203). When `on` is False (piped /
    NO_COLOR / CI) return the plain path string — scripts and logs never see escape sequences.
    The visible text is still the full path, so copy-paste works even where hyperlinks don't."""
    p = Path(path)
    text = str(p)
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
