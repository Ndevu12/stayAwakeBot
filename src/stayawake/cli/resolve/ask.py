#!/usr/bin/env python3
"""Put what saw cannot decide to the operator and read the answer: one uncertain file, or the files
one delivery commit added.

For a file, `remove`/`r`/`yes`/`y` removes it, `restore`/`re` and `supply`/`su` keep it with a
clean version where offered, and anything else keeps it. For a delivery, `all` or the numbers choose
files, then `yes` takes them out; Enter keeps them all; end of input or unclear answers leave the
question unanswered.
"""
from __future__ import annotations

import sys
from typing import TextIO

from stayawake.bots.security.pr.resolve import (KEEP, REMOVE, RESTORE, SUPPLY, TAKE_OUT,
                                                UNANSWERED, DeliveryAnswer, DeliveryQuestion,
                                                Resolution, UncertainItem)
from stayawake.cli.resolve.render import (FOLDERS_LISTED, NAMES_LISTED_PER_FOLDER,
                                         delivery_groups, render_delivery, render_item)
from stayawake.utils import prompt, textsafe

_REMOVE = frozenset({"remove", "r", "yes", "y"})
_RESTORE = frozenset({"restore", "re"})
_SUPPLY = frozenset({"supply", "su"})
_KEEP = frozenset({"keep", "k", "no", "n", "skip", "s", ""})
_MAX_TRIES = 3


def _question(can_restore: bool, can_supply: bool) -> str:
    """The prompt line offering the actions available for this item, each naming how far it reaches."""
    parts = ["type 'remove' to delete it from every commit that carries it"]
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


_DELIVERY_KEEP = frozenset({"keep", "k", "no", "n", ""})
_HABITUAL_YES = frozenset({"yes", "y", "remove", "r"})
_CHOOSE = ("type 'all' to take out every file listed, or the numbers to take out (e.g. 1 2.3), "
           "or press Enter to keep them all > ")
_CONFIRM = "type 'yes' to take them out, or press Enter to keep them all > "
_SHOWN_IN_CONFIRMATION = 3


def _number(text: str, highest: int) -> int | None:
    """Read a listed number. Takes the text and the highest number listed. Returns the number, or
    None when the text is not one of them."""
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= highest:
        return None
    return int(text)


def _chosen(answer: str, groups: list[tuple[str, list[str]]], every: list[str]) -> list[str] | None:
    """Read which files an answer chooses. Takes the answer, the numbered groups and every file.
    Returns the chosen paths, or None when the answer names nothing that is listed."""
    words = answer.replace(",", " ").split()
    if words == ["all"]:
        return list(every)
    chosen: list[str] = []
    for word in words:
        group_text, dot, entry_text = word.partition(".")
        group = _number(group_text, len(groups))
        if group is None:
            return None
        paths = groups[group - 1][1]
        if not dot:
            chosen += paths
            continue
        entry = _number(entry_text, min(len(paths), NAMES_LISTED_PER_FOLDER))
        if entry is None:
            return None
        chosen.append(paths[entry - 1])
    return list(dict.fromkeys(chosen)) or None


def _confirmed(chosen: list[str], stdin, stderr) -> str:
    """Ask the operator to confirm taking files out. Takes the chosen paths and the streams.
    Returns `TAKE_OUT`, `KEEP` or `UNANSWERED`."""
    names = ", ".join(textsafe.plain(p) for p in chosen[:_SHOWN_IN_CONFIRMATION])
    more = len(chosen) - _SHOWN_IN_CONFIRMATION
    print(f"  saw will take out {len(chosen)} file(s) from every commit that still holds them as "
          f"they were added: {names}" + (f" and {more} more" if more > 0 else "") + ".",
          file=stderr)
    for _ in range(_MAX_TRIES):
        answer = prompt.ask_line("  " + _CONFIRM, stdin=stdin, stderr=stderr)
        if answer is None:
            return UNANSWERED
        choice = answer.strip().lower()
        if choice == "yes":
            return TAKE_OUT
        if choice in _DELIVERY_KEEP:
            return KEEP
    return UNANSWERED


def ask_delivery(question: DeliveryQuestion, *, stdin: TextIO | None = None,
                 stderr: TextIO | None = None) -> DeliveryAnswer:
    """Show one delivery and read which of its files the operator takes out. Takes the question and
    the streams. Returns the `DeliveryAnswer`: `KEEP` on Enter, `UNANSWERED` at end of input or
    after unclear answers."""
    stderr = sys.stderr if stderr is None else stderr
    print(render_delivery(question), file=stderr)
    groups = delivery_groups(question)[:FOLDERS_LISTED]
    every = [f.path for f in question.files]
    hint = ""
    for _ in range(_MAX_TRIES):
        answer = prompt.ask_line("  " + hint + _CHOOSE, stdin=stdin, stderr=stderr)
        if answer is None:
            return DeliveryAnswer(UNANSWERED)
        choice = answer.strip().lower()
        if choice in _DELIVERY_KEEP:
            return DeliveryAnswer(KEEP)
        if choice in _HABITUAL_YES:
            hint = f"'{textsafe.plain(choice)}' is not an answer here — "
            continue
        chosen = _chosen(choice, groups, every)
        if chosen is None:
            hint = "that names nothing listed — "
            continue
        decision = _confirmed(chosen, stdin, stderr)
        return DeliveryAnswer(decision, tuple(chosen) if decision == TAKE_OUT else ())
    return DeliveryAnswer(UNANSWERED)
