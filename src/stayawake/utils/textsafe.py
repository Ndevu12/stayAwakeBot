#!/usr/bin/env python3
"""Output-encoding for untrusted strings — the safe way to render an attacker-controlled value
(a repo path, a finding reason, a git ref) into a GitHub Markdown body or a terminal / GitHub
Actions log.
"""
from __future__ import annotations

import unicodedata


def sanitize(s: str, limit: int = 300) -> str:
    """Neutralize a possibly attacker-controlled string for rendering INSIDE a Markdown code span.
    Any control/format char, line/paragraph separator, or bidi-override (Unicode category C*/Zl/Zp
    — newlines, NEL, U+2028/9, RLO, …) becomes a space so it can't break the list item, smuggle
    markup, or spoof text direction; backticks are replaced so it can't break OUT of the code span;
    length is bounded so a hostile value can't bloat the body. Because callers wrap the result in a
    code span (`code`), inline markup like `[x](y)` / `<img>` renders literally — so the value MUST
    stay inside a code span, never bare. (Invariant #5 of; fuller contract in.)"""
    out = "".join(ch if not (unicodedata.category(ch)[0] == "C"
                             or unicodedata.category(ch) in ("Zl", "Zp")) else " "
                  for ch in str(s))
    return out.replace("`", "ʼ")[:limit]


def code(s: str, limit: int = 300) -> str:
    """Render an untrusted string as safe Markdown inline code — the ONLY safe way to show an
    attacker-controlled value in a body (the surrounding code span neutralizes all Markdown/HTML;
    `sanitize` keeps the span from being closed early). Never render such a value bare."""
    return f"`{sanitize(s, limit)}`"


def quoted(s: str, limit: int = 300) -> str:
    """An untrusted value shown as a quoted span on a TERMINAL line — `code`'s sibling for the other
    surface. `code` quotes for Markdown and so escapes Markdown; this quotes for a terminal and so
    escapes what a terminal and a CI log parse. Same shape, same guarantee, different threat."""
    return f"`{plain(s, limit)}`"


def table_cell(s: str, limit: int = 300) -> str:
    """An untrusted value inside a Markdown TABLE cell. `code` is not enough there: GFM splits a row
    on `|` even within a code span, so one crafted path silently shifts every column after it."""
    return code(s, limit).replace("|", "\\|")


def plain(s: str, limit: int = 300) -> str:
    """Sanitize an untrusted string (a repo path, a finding reason/command) for a PLAIN-TEXT line
    on the terminal or a GitHub Actions log — safe to print ANYWHERE, including at line-start.
    Control chars, newlines, line/paragraph separators and bidi (Unicode C*/Zl/Zp) all become spaces
    (no line break / direction spoof), and the two GitHub Actions workflow-command introducers are
    defanged. Authoritatively (actions/runner `ActionCommand.cs`): the `::cmd::` form is parsed only
    when a line StartsWith `::`, but the legacy `##[cmd]` form is matched ANYWHERE in a line
    (`IndexOf("##[")`) — so a crafted path could inject `##[error]`/`##[group]` MID-line. Breaking
    both tokens means neither can form regardless of position or runner version. Bounded. Sibling of
    `sanitize` (which targets Markdown code spans)."""
    out = "".join(" " if (unicodedata.category(ch)[0] == "C"
                          or unicodedata.category(ch) in ("Zl", "Zp")) else ch
                  for ch in str(s))
    return out.replace("##[", "##(").replace("::", ": :").strip()[:limit]
