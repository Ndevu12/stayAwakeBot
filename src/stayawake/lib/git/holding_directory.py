#!/usr/bin/env python3
"""The holding directory `saw govern` checks an update in: the entries saw puts there, the refusal of
one inside a git repository, and clearing it of saw's own entries."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from stayawake.lib.git.inside_a_repository import lies_inside_a_repository, marks_a_repository
from stayawake.utils import folderlock, pathsafe

REPOSITORY = "repo.git"
WORK_TREE = "work"
NO_HOOKS = "no-hooks"
STATE = "state.json"
STATE_BEING_WRITTEN = STATE + ".tmp"
_SAW_ENTRIES = (STATE, STATE_BEING_WRITTEN, REPOSITORY, WORK_TREE, NO_HOOKS)
_KEPT_ENTRIES = (folderlock.LOCK_NAME,)
_POINTS_AT = b"gitdir: "

OVERLAPS_THE_FOLDER = "the holding directory must be outside the open folder"
OUTSIDE_EVERY_REPOSITORY = "the holding directory must be outside every git repository"
HOLDS_OTHER_FILES = "the holding directory holds files saw did not put there"
NOT_A_FOLDER = "the holding directory is not a folder"
NOT_CLEARED = "the holding directory could not be cleared"


def in_a_repository(into: Path) -> str:
    """Refuse a holding directory inside any git repository. Takes the holding directory. Returns
    the refusal, or "" when it lies outside every repository."""
    return OUTSIDE_EVERY_REPOSITORY if lies_inside_a_repository(into) else ""


def overlaps(into: Path, places) -> str:
    """Refuse a holding directory that is one of the places, lies inside one or holds one. Takes the
    holding directory and the places. Returns the refusal, or "" when it is apart from them all."""
    holding = Path(into).resolve()
    for place in places:
        resolved = Path(place).resolve()
        if any(_same_place(holding, step) for step in (resolved, *resolved.parents)):
            return OVERLAPS_THE_FOLDER
        if any(_same_place(resolved, step) for step in holding.parents):
            return OVERLAPS_THE_FOLDER
    return ""


def clear(into: Path) -> str:
    """Remove the entries saw puts in a holding directory, each by its name, and nothing else: a run's
    hold on it stays. Takes the holding directory. Returns the refusal, or "" when it is cleared."""
    holding = Path(into)
    if not os.path.lexists(holding):
        return ""
    if not holding.is_dir():
        return NOT_A_FOLDER
    try:
        names = set(os.listdir(holding))
    except OSError:
        return NOT_CLEARED
    if _holds_what_saw_did_not_put(holding, names):
        return HOLDS_OTHER_FILES
    try:
        for name in _SAW_ENTRIES:
            if name in names:
                _remove(holding / name)
    except OSError:
        return NOT_CLEARED
    return ""


def holds_other_files(into: Path) -> str:
    """Refuse a holding directory that holds an entry saw does not put there. Takes the holding
    directory. Returns the refusal, or "" when saw's entries are all it holds."""
    try:
        names = set(os.listdir(into)) if Path(into).is_dir() else set()
    except OSError:
        return HOLDS_OTHER_FILES
    return HOLDS_OTHER_FILES if _holds_what_saw_did_not_put(Path(into), names) else ""


def _holds_what_saw_did_not_put(holding: Path, names: set[str]) -> bool:
    """Tell whether a holding directory holds an entry under a name saw does not use, or a
    repository under one of saw's names other than the repository and working tree saw links to
    each other. Takes the holding directory and the names of its entries. Returns the answer."""
    if names - set(_SAW_ENTRIES) - set(_KEPT_ENTRIES):
        return True
    linked = _links_its_working_tree(holding)
    for name in names & set(_SAW_ENTRIES):
        entry = holding / name
        if os.path.islink(entry) or not marks_a_repository(entry):
            continue
        if not (linked and name in (REPOSITORY, WORK_TREE)):
            return True
    return False


def _links_its_working_tree(holding: Path) -> bool:
    """Tell whether the working tree in a holding directory points git at the repository beside it,
    as saw writes it. Takes the holding directory. Returns the answer."""
    work = holding / WORK_TREE
    if os.path.islink(work):
        return False
    pointer = pathsafe.read_regular_no_follow(work / ".git", 1 << 12)
    if pointer is None or not pointer.startswith(_POINTS_AT):
        return False
    named = Path(os.fsdecode(pointer[len(_POINTS_AT):].rstrip(b"\r\n")))
    named = named if named.is_absolute() else work / named
    return _same_place(Path(os.path.realpath(named)), Path(os.path.realpath(holding / REPOSITORY)))


def _remove(entry: Path) -> None:
    """Remove one entry: a folder with what it holds, else the file or link itself. Takes the entry.
    Returns nothing."""
    if entry.is_dir() and not entry.is_symlink():
        shutil.rmtree(entry)
    else:
        entry.unlink()


def _same_place(one: Path, other: Path) -> bool:
    """Tell whether two paths name one place on disk. Takes both. Returns the answer, comparing the
    paths themselves when either does not exist."""
    try:
        return os.path.samefile(one, other)
    except OSError:
        return one == other
