#!/usr/bin/env python3
"""The folder saw keeps its records in, under the operator's cache folder, and every read and write
of a record: none while that folder, or the folder the record itself lies in, is inside a git
repository."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from stayawake.lib.git.inside_a_repository import lies_inside_a_repository
from stayawake.utils import atomicwrite, env
from stayawake.utils.streaming import say

NOT_KEPT = (f"Every check starts over because {env.XDG_CACHE_HOME} lies inside a git repository. "
            f"Set {env.XDG_CACHE_HOME} to a folder outside every git repository.")
_told: set[str] = set()


class NotKept(OSError):
    """A record read or written while saw's record folder lies inside a git repository."""


def folder() -> Path:
    """Return the folder saw keeps its records in."""
    return Path(env.xdg_cache_home()) / "saw"


def path(*parts: str) -> Path:
    """Name a record in saw's record folder. Takes the parts of its name. Returns the path."""
    return folder().joinpath(*parts)


def kept(where: "Path | None" = None) -> bool:
    """Tell whether saw's record folder, and the folder a record lies in once every link to it is
    followed, lie outside every git repository, asked anew each time. Takes the record, None for the
    record folder alone. Returns the answer."""
    return _outside_every_repository(None if where is None else Path(os.path.realpath(where)).parent)


def _outside_every_repository(place: "Path | None") -> bool:
    """Tell whether saw's record folder and a folder for records lie outside every git repository.
    Takes the folder, None for the record folder alone. Returns the answer."""
    places = [Path(os.path.realpath(folder()))]
    if place is not None and Path(os.path.realpath(place)) != places[0]:
        places.append(Path(os.path.realpath(place)))
    return not any(lies_inside_a_repository(each) for each in places)


def not_kept() -> str:
    """Say that saw keeps no records, when its record folder lies inside a git repository. Returns
    the sentence, or ""."""
    return "" if kept() else NOT_KEPT


def read_text(where: Path) -> str:
    """Read a record's text. Takes its path. Returns the text. Raises `OSError` when it cannot be
    read, `NotKept` while saw keeps no records there."""
    if not kept(where):
        raise NotKept(NOT_KEPT)
    return Path(where).read_text(encoding="utf-8")


def read_back(where: Path, limit: int, *, at_a_link: str = atomicwrite.REFUSE_A_LINK) -> "bytes | None":
    """Read a record saw wrote, as `atomicwrite.read_back` reads it, while saw keeps records. Takes
    its path, the most bytes to read and how its name was written. Returns the bytes, or None."""
    return atomicwrite.read_back(where, limit, at_a_link=at_a_link) if kept(where) else None


def replace(where: Path, text: "str | bytes", *, mode: "int | None" = 0o600,
            at_a_link: str = atomicwrite.REFUSE_A_LINK) -> bool:
    """Write a record in one step, as `atomicwrite.replace` writes it. Takes its path, its contents,
    its mode and what to do at a link at its name. Returns whether it was written, False while saw
    keeps no records, which it says once per run."""
    if not kept(where):
        _tell_once()
        return False
    return atomicwrite.replace(where, text, mode=mode, at_a_link=at_a_link)


def make_folder(where: Path) -> None:
    """Make a folder for records and every missing folder above it. Takes the folder. Raises
    `OSError` when it cannot be made, `NotKept` while saw keeps no records."""
    if not _outside_every_repository(Path(where)):
        _tell_once()
        raise NotKept(NOT_KEPT)
    atomicwrite.make_folder(where)


def remove(where: Path) -> None:
    """Remove a record. Takes its path. Returns nothing, and leaves it while saw keeps no records."""
    if not kept(where):
        return
    try:
        Path(where).unlink()
    except OSError:
        pass


def _tell_once() -> None:
    """Say on standard error, once per run, that saw keeps no records."""
    if NOT_KEPT not in _told:
        _told.add(NOT_KEPT)
        say(NOT_KEPT, no_stream=True, out=sys.stderr)
