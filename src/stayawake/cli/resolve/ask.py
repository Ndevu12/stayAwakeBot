#!/usr/bin/env python3
"""Put one uncertain file to the operator and read a keep/remove/restore/supply answer.

The safe rendering is written to the error stream and one line is read from input. `remove`/`r`/
`yes`/`y` removes; `restore`/`re` puts back the clean version saw found; `supply`/`su` replaces it
with a file the operator names; both are offered only when they apply. Every other answer — including
a blank line and end of input — keeps. An unclear answer is re-asked a few times before keeping.
"""
from __future__ import annotations

import sys
from typing import TextIO

from stayawake.bots.security.pr.resolve import (KEEP, REMOVE, RESTORE, SUPPLY, Resolution,
                                                UncertainItem)
from stayawake.cli.resolve.render import render_item
from stayawake.utils import prompt

_REMOVE = frozenset({"remove", "r", "yes", "y"})
_RESTORE = frozenset({"restore", "re"})
_SUPPLY = frozenset({"supply", "su"})
_KEEP = frozenset({"keep", "k", "no", "n", "skip", "s", ""})
_MAX_TRIES = 3


def _question(can_restore: bool, can_supply: bool) -> str:
    """The prompt line offering the actions available for this item."""
    parts = ["type 'remove' to delete"]
    if can_restore:
        parts.append("'restore' to put back the clean version")
    if can_supply:
        parts.append("'supply' to replace it with a file you provide")
    return ", ".join(parts) + ", or press Enter to keep > "


def _read_supplied(stdin: TextIO | None, stderr: TextIO | None) -> bytes | None:
    """Read a path from the operator and return that file's bytes, or None if it cannot be read."""
    path = prompt.ask_line("  path to the replacement file > ", stdin=stdin, stderr=stderr)
    if not path or not path.strip():
        return None
    try:
        with open(path.strip(), "rb") as handle:
            return handle.read()
    except OSError:
        return None


def ask_resolution(item: UncertainItem, *, stdin: TextIO | None = None,
                   stderr: TextIO | None = None) -> Resolution:
    """Show `item` and return the operator's `Resolution`. Keeps on a blank answer or end of input."""
    stderr = sys.stderr if stderr is None else stderr
    print(render_item(item), file=stderr)
    can_restore = item.restore_candidate is not None
    can_supply = item.keep_content
    question = _question(can_restore, can_supply)
    for _ in range(_MAX_TRIES):
        answer = prompt.ask_line(question, stdin=stdin, stderr=stderr)
        if answer is None:
            break
        choice = answer.strip().lower()
        if choice in _REMOVE:
            return Resolution(REMOVE)
        if can_restore and choice in _RESTORE:
            return Resolution(RESTORE, restore=item.restore_candidate)
        if can_supply and choice in _SUPPLY:
            content = _read_supplied(stdin, stderr)
            if content is not None:
                return Resolution(SUPPLY, supply=content)
            continue
        if choice in _KEEP:
            return Resolution(KEEP)
    return Resolution(KEEP)
