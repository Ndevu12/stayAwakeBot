#!/usr/bin/env python3
"""The holding directory `saw govern` checks an update in: the entries saw puts there, the refusal of
one that overlaps the open folder, and clearing it of saw's own entries."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from stayawake.utils import folderlock

REPOSITORY = "repo.git"
WORK_TREE = "work"
NO_HOOKS = "no-hooks"
STATE = "state.json"
STATE_BEING_WRITTEN = STATE + ".tmp"
_SAW_ENTRIES = (STATE, STATE_BEING_WRITTEN, REPOSITORY, WORK_TREE, NO_HOOKS)
_KEPT_ENTRIES = (folderlock.LOCK_NAME,)

OVERLAPS_THE_FOLDER = "the holding directory must be outside the open folder"
HOLDS_OTHER_FILES = "the holding directory holds files saw did not put there"
NOT_A_FOLDER = "the holding directory is not a folder"
NOT_CLEARED = "the holding directory could not be cleared"


def overlaps(repo: Path, into: Path) -> str:
    """Refuse a holding directory that is the open folder, lies inside it or holds it. Takes the open
    folder and the holding directory. Returns the refusal, or "" when the two are apart."""
    folder, holding = Path(repo).resolve(), Path(into).resolve()
    if any(_same_place(holding, place) for place in (folder, *folder.parents)):
        return OVERLAPS_THE_FOLDER
    if any(_same_place(folder, place) for place in holding.parents):
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
    if names - set(_SAW_ENTRIES) - set(_KEPT_ENTRIES):
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
    return HOLDS_OTHER_FILES if names - set(_SAW_ENTRIES) - set(_KEPT_ENTRIES) else ""


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
