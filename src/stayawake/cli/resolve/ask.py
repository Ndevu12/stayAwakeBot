#!/usr/bin/env python3
"""Put one uncertain file to the operator and read a keep/remove/restore answer.

The safe rendering is written to the error stream and one line is read from input. `remove`/`r`/
`yes`/`y` removes; `restore`/`re` puts back the clean version saw found (offered only when there is
one); every other answer — including a blank line and end of input — keeps. An unclear answer is
re-asked a few times before keeping.
"""
from __future__ import annotations

import sys
from typing import TextIO

from stayawake.bots.security.pr.resolve import KEEP, REMOVE, RESTORE, Resolution, UncertainItem
from stayawake.cli.resolve.render import render_item
from stayawake.utils import prompt

_REMOVE = frozenset({"remove", "r", "yes", "y"})
_RESTORE = frozenset({"restore", "re"})
_KEEP = frozenset({"keep", "k", "no", "n", "skip", "s", ""})
_PROMPT = "Remove this file? type 'remove' to delete, or press Enter to keep > "
_PROMPT_RESTORE = ("Remove, restore, or keep? type 'remove' to delete, 'restore' to put back the "
                   "clean version, or press Enter to keep > ")
_MAX_TRIES = 3


def ask_resolution(item: UncertainItem, *, stdin: TextIO | None = None,
                   stderr: TextIO | None = None) -> Resolution:
    """Show `item` and return the operator's `Resolution`. Keeps on a blank answer or end of input."""
    stderr = sys.stderr if stderr is None else stderr
    print(render_item(item), file=stderr)
    can_restore = item.restore_candidate is not None
    question = _PROMPT_RESTORE if can_restore else _PROMPT
    for _ in range(_MAX_TRIES):
        answer = prompt.ask_line(question, stdin=stdin, stderr=stderr)
        if answer is None:
            break
        choice = answer.strip().lower()
        if choice in _REMOVE:
            return Resolution(REMOVE)
        if can_restore and choice in _RESTORE:
            return Resolution(RESTORE, item.restore_candidate)
        if choice in _KEEP:
            return Resolution(KEEP)
    return Resolution(KEEP)
