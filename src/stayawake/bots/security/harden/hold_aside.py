#!/usr/bin/env python3
"""Move whatever is where a denial goes aside, to a name beside it in the same folder, and put it back."""
from __future__ import annotations

import datetime
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from stayawake.bots.security.hygiene.staging_kit import HELD_ASIDE_MARK, held_aside
from stayawake.utils import atomicwrite, hostdenial

__all__ = ["HELD_ASIDE_MARK", "Moved", "Seen", "held_aside", "move_aside", "put_back", "put_back_this", "seen_at"]

_MOST_AT_ONE_TIME = 100

PUT_BACK, KEPT_ASIDE, PATH_TAKEN, NOT_PUT_BACK, NOTHING_HELD = (
    "put-back", "kept-aside", "path-taken", "not-put-back", "nothing-held")


@dataclass(frozen=True)
class Seen:
    """What was at a location when it was looked at: its device, inode, kind and when it last changed."""

    device: int
    inode: int
    kind: int
    changed: int = 0

    def is_the_same_object(self, other: "Seen | None") -> bool:
        """Tell whether `other` is this object, however it has changed since. Takes what was seen."""
        return other is not None and (self.device, self.inode, self.kind) == (other.device, other.inode,
                                                                                other.kind)


@dataclass(frozen=True)
class Moved:
    """Where what was at a location went, or None; and whether something else was found moved."""

    held: Path | None = None
    mismatch: bool = False


def _seen(found: os.stat_result) -> Seen:
    return Seen(found.st_dev, found.st_ino, stat.S_IFMT(found.st_mode), found.st_ctime_ns)


def seen_at(path: Path) -> Seen | None:
    """Return what is at `path`, not following a link. Takes the location. Returns None when nothing
    is there or it cannot be read."""
    try:
        return _seen(path.lstat())
    except OSError:
        return None


@dataclass
class Held:
    """What is at a location, looked at once and, when it opens without side effects (a folder or a
    regular file), held open, so its inode cannot be given to anything else while it is acted on."""

    seen: Seen
    fd: int | None = None

    def close(self) -> None:
        """Let go of what is held."""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def hold(path: Path) -> Held | None:
    """Look at what is at `path` and hold it. Takes the location. Returns what is held, which the caller
    closes, or None when nothing is there or a folder or file there cannot be opened as one."""
    seen = seen_at(path)
    if seen is None:
        return None
    if seen.kind == stat.S_IFDIR:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    elif seen.kind == stat.S_IFREG:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    else:
        return Held(seen)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    opened = _seen(os.fstat(fd))
    if not opened.is_the_same_object(seen_at(path)):
        os.close(fd)
        return None
    return Held(opened, fd)


def _still(path: Path, held: Held) -> bool:
    """Tell whether `path` still names what is held: through the descriptor when there is one, and
    otherwise by what was seen, down to when it last changed."""
    here = seen_at(path)
    if held.fd is None:
        return here == held.seen
    try:
        return _seen(os.fstat(held.fd)).is_the_same_object(here)
    except OSError:
        return False


def _free_name(path: Path, now: datetime.datetime) -> str | None:
    """Return a name beside `path` nothing has, stamped with the time. Takes the location and the time.
    Returns None when every name for that second is taken."""
    first = f"{path.name}{HELD_ASIDE_MARK}{now.strftime('%Y%m%dT%H%M%SZ')}"
    for count in range(1, _MOST_AT_ONE_TIME + 1):
        name = first if count == 1 else f"{first}-{count}"
        if not os.path.lexists(path.parent / name):
            return name
    return None


def move_aside(path: Path, held: Held, *, now: datetime.datetime | None = None) -> Moved:
    """Rename what is at `path` to a free name beside it, when it is still what is held; a run as an
    administrator first takes off a lock that is not a denial of saw's. Takes the location, what is held
    there and the time (default: now). Returns where it went; when something else was renamed, it is
    renamed back and the result says so."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not _still(path, held):
        return Moved()
    if hostdenial.privileged() and hostdenial.held_by(path) is None and hostdenial.immutable(path):
        hostdenial.clear_immutable(path)
    name = _free_name(path, now)
    if name is None or not held.seen.is_the_same_object(seen_at(path)):
        return Moved()
    try:
        atomicwrite.rename_beside(path.parent, path.name, name)
    except OSError:
        return Moved()
    target = path.parent / name
    if _still(target, held) if held.fd is not None else held.seen.is_the_same_object(seen_at(target)):
        return Moved(held=target)
    try:
        atomicwrite.rename_beside(path.parent, name, path.name)
    except OSError:
        pass
    return Moved(mismatch=True)


def put_back_this(path: Path, held: Path, seen: Seen) -> bool:
    """Rename what was moved aside back to `path`, while `path` is free and it is still what was moved.
    Takes the location, where it was held and what was seen. Returns True when it is back."""
    if not seen.is_the_same_object(seen_at(held)):
        return False
    try:
        atomicwrite.rename_beside(path.parent, held.name, path.name)
    except OSError:
        return False
    return seen.is_the_same_object(seen_at(path))


def put_back(path: Path, keeps_aside) -> str:
    """Rename what saw last moved aside from `path` back to it, while `path` is free, unless it is
    something to keep aside. Takes the location and `keeps_aside(held) -> bool`; an OSError from it
    leaves it held. Returns PUT_BACK, KEPT_ASIDE, PATH_TAKEN, NOT_PUT_BACK or NOTHING_HELD."""
    try:
        held = held_aside(path)
    except OSError:
        return NOT_PUT_BACK
    if not held:
        return NOTHING_HELD
    newest = held[-1]
    if os.path.lexists(path):
        return PATH_TAKEN
    try:
        if keeps_aside(newest):
            return KEPT_ASIDE
    except OSError:
        return NOT_PUT_BACK
    seen = seen_at(newest)
    return PUT_BACK if seen is not None and put_back_this(path, newest, seen) else NOT_PUT_BACK
