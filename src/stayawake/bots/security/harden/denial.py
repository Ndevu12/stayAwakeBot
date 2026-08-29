#!/usr/bin/env python3
"""Create one host-level denial, then read it back."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils import hostdenial


ENFORCING = "enforcing"
UNKNOWN = "unknown"
OCCUPIED = "occupied"


@dataclass(frozen=True)
class PathOutcome:
    path: Path
    state: str
    detail: str


def _occupied(path: Path) -> PathOutcome:
    return PathOutcome(path, OCCUPIED,
                       "already had something in it, so it was not changed")


def _unknown(path: Path, why: str) -> PathOutcome:
    return PathOutcome(path, UNKNOWN, why)


def _real_dir(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    return not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode)


def _trusted_ancestor(path: Path) -> bool:
    """Whether creating under `path` stays where the caller named.

    A symbolic link is only accepted when root owns the link itself: the system's own
    (`/var` → `/private/var`) resolves that way, and nobody without root could have put it there.
    A link anyone else could have planted redirects the write and is refused."""
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return st.st_uid == 0 and path.is_dir()
    return stat.S_ISDIR(st.st_mode)


def _create_where_it_was_named(path: Path) -> bool:
    """Create `path` and any missing parent, one component at a time.

    `mkdir(parents=True)` resolves each ancestor, so a planted parent link would put the denial
    wherever that link points instead of at the location that was named."""
    for ancestor in reversed(path.parents):
        try:
            ancestor.lstat()
        except FileNotFoundError:
            try:
                os.mkdir(ancestor)
            except OSError:
                return False
        except OSError:
            return False
        if not _trusted_ancestor(ancestor):
            return False
    try:
        os.mkdir(path)
    except OSError:
        return False
    return _real_dir(path)


def _still_empty_dir(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    return hostdenial.empty_dir(path)


def apply_one(path: Path) -> PathOutcome:
    """Create the denial at `path` if the location is free; never remove what is already there."""
    if hostdenial.holds(path):
        return PathOutcome(path, ENFORCING, "in place")
    try:
        st = path.lstat()
    except FileNotFoundError:
        st = None
    except OSError:
        return _unknown(path, "could not be read")
    if st is not None:
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or not hostdenial.empty_dir(path):
            return _occupied(path)
    elif not _create_where_it_was_named(path):
        return _unknown(path, "could not be created")
    try:
        os.chmod(path, 0o555, follow_symlinks=False)
        os.chown(path, 0, 0, follow_symlinks=False)
    except (OSError, NotImplementedError):
        return _unknown(path, "could not be written")
    if not _still_empty_dir(path):
        return _occupied(path)
    if not hostdenial.set_immutable(path):
        return _unknown(path, "could not be verified")
    if not hostdenial.holds(path):
        return _unknown(path, "could not be verified")
    return PathOutcome(path, ENFORCING, "in place")
