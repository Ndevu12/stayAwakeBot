#!/usr/bin/env python3
"""The bare-`saw` welcome banner and the `saw intro` tour (issue #1177).

Pure string builders — no I/O, no state, no new dependencies. The dispatcher prints
`render_welcome()` when `saw` runs with no command; `saw intro` prints `render_intro()`.

Colour is applied for the `ColorLevel` the terminal supports (see `core.terminal`):

  * TRUECOLOR / ANSI256 / ANSI16 → the mint wordmark degrades gracefully across palettes;
  * NONE → the SAME block art and layout with **zero ANSI**, so piped / CI / NO_COLOR / dumb
    output stays clean text.

A dependency-light leaf like `_meta` (it imports only `core.terminal`), so the dispatcher and
the `intro` command import it without cycles. The wordmark is a plain-string constant, composed
from fixed-width letter grids so its columns always align, and each render branch is testable in
isolation.
"""
from __future__ import annotations

from stayawake.core.terminal import ColorLevel

# ── the endorsed "SAW" wordmark, composed from fixed-width letter grids (columns always align) ──
_S = [" █████", "██    ", " ████ ", "    ██", "█████ "]
_A = ["  ███  ", " █████ ", "██   ██", "███████", "██   ██"]
_W = ["██   ██", "██   ██", "██ █ ██", "███████", " ██ ██ "]
SAW_LOGO = "\n".join("  ".join(cells) for cells in zip(_S, _A, _W))
_LOGO_LINES = SAW_LOGO.split("\n")
_LOGO_W = max(len(ln) for ln in _LOGO_LINES)

# ── semantic palette: (truecolor rgb, ansi-256, ansi-16 SGR) ──────────────────────────────
_MINT  = ((126, 231, 176), 114, "92")
_GREEN = ((76, 208, 125), 78, "32")
_CYAN  = ((95, 211, 221), 80, "96")
_DIM   = ((122, 133, 148), 244, "90")
_FAINT = ((88, 96, 110), 240, "90")
_WHITE = ((240, 246, 252), 231, "97")
_FG    = ((201, 211, 222), 252, "37")

_URL = "github.com/Ndevu12/stayAwakeBot"


def _paint(level: ColorLevel, text: str, spec, *, bold: bool = False, italic: bool = False) -> str:
    if level is ColorLevel.NONE:
        return text
    parts: list[str] = []
    if bold:
        parts.append("1")
    if italic:
        parts.append("3")
    rgb, c256, c16 = spec
    if level is ColorLevel.TRUECOLOR:
        parts.append("38;2;%d;%d;%d" % rgb)
    elif level is ColorLevel.ANSI256:
        parts.append("38;5;%d" % c256)
    else:
        parts.append(c16)
    return "\033[" + ";".join(parts) + "m" + text + "\033[0m"


def _logo_block(level: ColorLevel, tails: list[tuple[str, tuple, bool] | None]) -> list[str]:
    """The mint wordmark, each row optionally trailed by a coloured tagline (text, spec, italic)."""
    out = []
    for i, ln in enumerate(_LOGO_LINES):
        row = _paint(level, ln, _MINT, bold=True) + " " * (_LOGO_W - len(ln))
        tail = tails[i] if i < len(tails) else None
        if tail:
            text, spec, italic = tail
            row += "   " + _paint(level, text, spec, italic=italic)
        out.append(row)
    return out


def render_welcome(level: ColorLevel, version: str) -> str:
    """The screen bare `saw` prints: wordmark, one-liners, a get-started block, and links."""
    def C(text, spec, **kw):
        return _paint(level, text, spec, **kw)

    lines = [""]
    lines += _logo_block(level, [
        ("the sentinel saw the worm", _DIM, True),
        None,
        ("supply-chain worm hunter", _GREEN, False),
        ("offline · persists nothing", _DIM, False),
        None,
    ])
    lines += ["", C("Get started", _WHITE, bold=True)]
    cmds = [
        ("saw scan .", "hunt this repo for supply-chain worms (read-only)"),
        ("saw audit", "credential · editor · CI hygiene"),
        ("saw intro", "a 60-second tour"),
        ("saw <command> -h", "help for any command"),
    ]
    w = max(len(c) for c, _ in cmds)
    for cmd, desc in cmds:
        lines.append("  " + C(cmd, _CYAN, bold=True) + " " * (w - len(cmd) + 3) + C(desc, _DIM))
    lines += ["", C(f"saw v{version} ", _DIM) + C("· ", _FAINT)
              + C("zero code runs at install", _GREEN) + C(" · ", _FAINT) + C(_URL, _CYAN), ""]
    return "\n".join(lines) + "\n"


def render_intro(level: ColorLevel, version: str) -> str:
    """The fuller `saw intro` tour: what it is, the verbs, why it's safe, and how to gate CI."""
    def C(text, spec, **kw):
        return _paint(level, text, spec, **kw)

    lines = [""]
    lines += _logo_block(level, [
        ("stayAwakeBot", _WHITE, False),
        ("the sentinel saw the worm", _DIM, True),
        None,
        ("detect · report · auto-fix", _GREEN, False),
        None,
    ])
    lines += [
        "", C("What it is", _WHITE, bold=True),
        C("  A local supply-chain worm hunter — it detects, reports, and auto-fixes", _DIM),
        C("  self-propagating malware: obfuscated loaders, fake fonts, VS Code", _DIM),
        C('  auto-run tasks, and stealth "evil merges".', _DIM),
        "", C("Three verbs", _WHITE, bold=True),
        "  " + C("saw scan ", _CYAN, bold=True) + C("  hunt worms (read-only) — ", _DIM)
        + C("the exit code IS the verdict", _FG),
        "  " + C("saw fix  ", _CYAN, bold=True) + C("  recover from git onto a clean branch; ", _DIM)
        + C("--pr", _MINT) + C(" opens a PR", _DIM),
        "  " + C("saw audit", _CYAN, bold=True) + C("  credential · editor · CI hygiene", _DIM),
        "", C("Why it's safe", _WHITE, bold=True),
        "  " + C("· runs ", _DIM) + C("zero code at install", _GREEN)
        + C(" (that's the very vector it hunts)", _DIM),
        "  " + C("· fully accurate ", _DIM) + C("offline", _GREEN)
        + C("; only sandbox-escaping -x is opt-in", _DIM),
        C("  · persists nothing by default", _DIM),
        "",
        C("Gate CI  ", _WHITE, bold=True) + C("saw scan", _CYAN, bold=True)
        + C("  →  exit 1 on infection fails the build", _DIM),
        C("Docs     ", _WHITE, bold=True) + C(_URL, _CYAN),
        C(f"saw v{version}", _FAINT), "",
    ]
    return "\n".join(lines) + "\n"
