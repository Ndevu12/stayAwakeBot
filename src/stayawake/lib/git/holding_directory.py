#!/usr/bin/env python3
"""The holding directory `saw govern` checks an update in: the entries saw puts there, the refusal of
one that overlaps the open folder, and clearing it of saw's own entries."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from stayawake.lib.git.run import UNTRUSTED, stdout
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


def repository_places(repo: Path) -> list[Path]:
    """List the places a holding directory stays apart from: the folder, and the top, git directory
    and common directory of the repository it belongs to. Takes the folder. Returns the places."""
    places = [Path(repo)]
    for asked in (["--absolute-git-dir", "--git-common-dir"], ["--show-toplevel"]):
        found = stdout(repo, ["rev-parse", "--path-format=absolute", *asked], context=UNTRUSTED)
        places += [Path(line) for line in found.splitlines() if line.strip()]
    return places


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
