#!/usr/bin/env python3
"""Whether a place lies inside a git repository: a work tree, a git directory or a bare repository,
found by the `.git` entries and git directories around it and by asking git."""
from __future__ import annotations

import os
from pathlib import Path

from stayawake.lib.git.run import UNTRUSTED, run

_NOT_A_REPOSITORY = "not a git repository (or any of the parent directories)"
_ACROSS_FILESYSTEMS = "GIT_DISCOVERY_ACROSS_FILESYSTEM"


def lies_inside_a_repository(path: Path) -> bool:
    """Tell whether git finds a place inside a work tree, a git directory or a bare repository, asked
    from the place or, when it does not exist yet, its nearest existing folder. Takes the place.
    Returns the answer, yes when git cannot answer."""
    place = Path(os.path.realpath(path))
    while not place.is_dir() and place != place.parent:
        place = place.parent
    if any(marks_a_repository(folder) for folder in (place, *place.parents)):
        return True
    asked = run(place, ["rev-parse", "--is-inside-work-tree", "--is-inside-git-dir", "--is-bare-repository"],
                env=_asking_from_anywhere(), context=UNTRUSTED)
    return not (asked is not None and asked.returncode != 0 and _NOT_A_REPOSITORY in (asked.stderr or ""))


def marks_a_repository(folder: Path) -> bool:
    """Tell whether a folder holds a `.git` entry of any kind or is itself a git directory. Takes the
    folder. Returns the answer, yes when an entry cannot be looked at."""
    return _may_exist(folder / ".git") or all(_may_exist(folder / name) for name in ("HEAD", "objects", "refs"))


def _may_exist(path: Path) -> bool:
    """Tell whether an entry exists, without following a link. Takes its path. Returns the answer, yes
    when it cannot be looked at."""
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return True


def _asking_from_anywhere() -> dict:
    """Return this process's environment with git's messages untranslated and its search for a
    repository crossing filesystems."""
    environment = {key: value for key, value in os.environ.items() if key != "LANGUAGE"}
    environment["LC_ALL"] = "C"
    environment[_ACROSS_FILESYSTEMS] = _true_unlike_the_inherited(_ACROSS_FILESYSTEMS)
    return environment


def _true_unlike_the_inherited(name: str) -> str:
    """Spell a true value for a git variable other than the way this process inherited it. Takes the
    variable's name. Returns the value."""
    return "true" if os.environ.get(name) == "1" else "1"
