#!/usr/bin/env python3
"""The bare-`saw` welcome banner and the `saw intro` tour (issue).

Pure string builders — no I/O, no state, no new dependencies. The dispatcher prints
`render_welcome()` when `saw` runs with no command; `saw intro` prints `render_intro()`.
"""
from __future__ import annotations

from stayawake.utils.terminal import ColorLevel

_S = [" █████", "██    ", " ████ ", "    ██", "█████ "]
_A = ["  ███  ", " █████ ", "██   ██", "███████", "██   ██"]
_W = ["██   ██", "██   ██", "██ █ ██", "███████", " ██ ██ "]
SAW_LOGO = "\n".join("  ".join(cells) for cells in zip(_S, _A, _W))
_LOGO_LINES = SAW_LOGO.split("\n")
_LOGO_W = max(len(ln) for ln in _LOGO_LINES)

_MINT  = ((126, 231, 176), 114, "92")
_GREEN = ((76, 208, 125), 78, "32")
_CYAN  = ((95, 211, 221), 80, "96")
_DIM   = ((122, 133, 148), 244, "90")
_FAINT = ((88, 96, 110), 240, "90")
_WHITE = ((240, 246, 252), 231, "97")

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
        ("the hunt, the clean, the host, the gate", _DIM, False),
        None,
    ])
    lines += ["", C("Get started", _WHITE, bold=True)]
    cmds = [
            ("saw scan .", "the repo, the lockfile, the install, and the host"),
            ("saw audit", "the machine — credentials, editor, start-up"),
            ("saw harden", "host controls, in place after a read-back"),
            ("saw intro", "a 60-second tour"),
            ("saw <command> -h", "help for any command"),
    ]
    w = max(len(c) for c, _ in cmds)
    for cmd, desc in cmds:
        lines.append("  " + C(cmd, _CYAN, bold=True) + " " * (w - len(cmd) + 3) + C(desc, _DIM))
    lines += ["", C(f"saw v{version} ", _DIM) + C("· ", _FAINT)
              + C("the hunt, the clean, the host, the gate", _GREEN) + C(" · ", _FAINT) + C(_URL, _CYAN), ""]
    return "\n".join(lines) + "\n"


def render_intro(level: ColorLevel, version: str) -> str:
    """The fuller `saw intro` tour: what it is, the work, and how to start."""
    def C(text, spec, **kw):
        return _paint(level, text, spec, **kw)

    lines = [""]
    lines += _logo_block(level, [
        ("stayAwakeBot", _WHITE, False),
        ("the sentinel saw the worm", _DIM, True),
        None,
        ("detect · remediate · prevent", _GREEN, False),
        None,
    ])
    lines += [
        "", C("What it is", _WHITE, bold=True),
        C("  A supply-chain worm hunter. It hunts where the worm lands:", _DIM),
        C("  repositories, lockfiles, installed packages, and the host.", _DIM),
        "", C("The work", _WHITE, bold=True),
        "  " + C("saw scan  ", _CYAN, bold=True) + C("  the tree and the host", _DIM),
        "  " + C("saw hook  ", _CYAN, bold=True) + C("  a clone, a pull, a switch, a rebase", _DIM),
        "  " + C("saw fix   ", _CYAN, bold=True) + C("  the previous version onto a pull request  ", _DIM)
        + C("--pr", _MINT),
        "  " + C("saw harden", _CYAN, bold=True) + C("  this machine", _DIM),
        "  " + C("saw guard ", _CYAN, bold=True) + C("  the merge", _DIM),
        "",
        C("Start    ", _WHITE, bold=True) + C("saw scan", _CYAN, bold=True)
        + C("  — the last line of the report is the verdict", _DIM),
        C("Docs     ", _WHITE, bold=True) + C(_URL, _CYAN),
        C(f"saw v{version}", _FAINT), "",
    ]
    return "\n".join(lines) + "\n"
