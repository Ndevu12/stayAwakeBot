#!/usr/bin/env python3
"""Put one uncertain file to the operator and read a keep/remove answer.

The safe rendering is written to the error stream and one line is read from input. `remove`/`r`/
`yes`/`y` removes; every other answer — including a blank line and end of input — keeps, so silence
never removes. An unclear answer is re-asked a few times before keeping.
"""
from __future__ import annotations

import sys
from typing import TextIO

from stayawake.bots.security.pr.resolve import Decision, UncertainItem
from stayawake.cli.resolve.render import render_item
from stayawake.utils import prompt

_REMOVE = frozenset({"remove", "r", "yes", "y"})
_KEEP = frozenset({"keep", "k", "no", "n", "skip", "s", ""})
_PROMPT = "Remove this file? type 'remove' to delete, or press Enter to keep > "
_MAX_TRIES = 3


def ask_decision(item: UncertainItem, *, stdin: TextIO | None = None,
                 stderr: TextIO | None = None) -> Decision:
    """Show `item` and return the operator's `Decision`. Keeps on a blank answer or end of input."""
    stderr = sys.stderr if stderr is None else stderr
    print(render_item(item), file=stderr)
    for _ in range(_MAX_TRIES):
        answer = prompt.ask_line(_PROMPT, stdin=stdin, stderr=stderr)
        if answer is None:
            break
        choice = answer.strip().lower()
        if choice in _REMOVE:
            return Decision(remove=True)
        if choice in _KEEP:
            return Decision(remove=False)
    return Decision(remove=False)
