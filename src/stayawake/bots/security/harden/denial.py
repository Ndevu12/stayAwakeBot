#!/usr/bin/env python3
"""Create one host-level denial, then read it back."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils import hostdenial


ENFORCING = "enforcing"
SELF_ENFORCING = "enforcing-as-you"
NEEDS_ROOT = "needs-root"
IN_A_LIVE_INSTALL = "in-a-live-install"
NOT_HERE_YET = "not-here-yet"
REMOVED = "removed"
NOTHING_TO_REMOVE = "nothing-to-remove"
UNKNOWN = "unknown"
OCCUPIED = "occupied"

_ROOT_DETAIL = "in place; only root can remove it"
_SELF_DETAIL = ("in place; anything running as you can remove it — run again with sudo to make it "
                "root-owned")


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


def _graded(path: Path) -> PathOutcome | None:
    """The outcome for a denial that is already there, or None when none is.

    A lock the operator holds is RAISED when there is privilege to finish the job — that is what
    the report tells them to re-run for. It used to be unreachable: the grade was decided by
    comparing the owner against the EFFECTIVE uid, which under `sudo` is root, so an
    operator-owned lock graded as nobody's and the run fell through to a `chmod` that an immutable
    directory refuses even from its owner. The advice said re-run with sudo; doing so reported the
    host as not denied while the locks were untouched.
    """
    held = hostdenial.held_by(path)
    if held == hostdenial.ROOT_HELD:
        return PathOutcome(path, ENFORCING, _ROOT_DETAIL)
    if held == hostdenial.SELF_HELD:
        if hostdenial.privileged():
            return _take_ownership(path)
        return PathOutcome(path, SELF_ENFORCING, _SELF_DETAIL)
    return None


def _take_ownership(path: Path) -> PathOutcome:
    """Raise a denial the operator holds to one root holds.

    The flag has to come off to change the owner and go back on afterwards, so this is only worth
    doing with the privilege to finish it — a half-done upgrade leaves the location open.
    """
    if not hostdenial.clear_immutable(path):
        return _unknown(path, "could not be raised to root")
    try:
        os.chown(path, 0, 0, follow_symlinks=False)
    except (OSError, NotImplementedError):
        hostdenial.set_immutable(path)
        return _unknown(path, "could not be raised to root")
    # The owner cannot be changed while the flag is set, so the location is briefly open. Anything
    # that arrives in that gap must NOT be sealed in: locking it would put content beyond the
    # operator's reach at the exact location this exists to keep empty.
    if not hostdenial.empty_dir(path):
        return _occupied(path)
    if not hostdenial.set_immutable(path) or not hostdenial.holds(path):
        return _unknown(path, "could not be verified")
    return PathOutcome(path, ENFORCING, _ROOT_DETAIL)


def _parent_is_here(path: Path) -> bool:
    """Whether the directory this denial would go IN already exists.

    A control creates the leaf, never the tree above it. Creating the tree meant a location named
    for a package manager the host does not have got that manager's prefix built for it — and an
    unreadable parent is treated as present, so "could not tell" is answered by the attempt and
    its read-back rather than by skipping in silence.
    """
    try:
        return stat.S_ISDIR(os.stat(path.parent).st_mode)
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _inside_a_node_installation(path: Path) -> bool:
    """Whether `path` sits inside a Node installation somebody manages.

    `<prefix>/lib/node` is a real resolution path, and locking it there is also locking a
    directory inside the install — after which `nvm uninstall`, `volta uninstall` and
    `brew uninstall node` all fail on it, with an error naming neither the flag nor this tool.
    The version manager's own removal is `rm -rf <prefix>`, and an immutable child defeats it.
    """
    prefix = path.parent.parent
    try:
        return (prefix / "bin" / "node").exists()
    except OSError:
        return False


def apply_one(path: Path) -> PathOutcome:
    """Create the denial at `path` if the location is free; never remove what is already there.

    Privilege is asked of the PATH, not of the command: most locations a payload stages into are
    the operator's own, and refusing to act on any of them until the whole run is root turns a
    control most people could have into one most people will not run.
    """
    already = _graded(path)
    if already is not None:
        return already
    if not _parent_is_here(path):
        return PathOutcome(path, NOT_HERE_YET,
                           "the directory this would go in is not on this machine, so nothing "
                           "was created")
    if _inside_a_node_installation(path):
        return PathOutcome(path, IN_A_LIVE_INSTALL,
                           "inside a Node installation — locking it here would stop that version "
                           "being removed or upgraded, so it was left as it stood")
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
        if not hostdenial.privileged() and not hostdenial.can_write_into(path):
            return PathOutcome(path, NEEDS_ROOT,
                               "this location is not yours to write to — run again with sudo")
        return _unknown(path, "could not be created")
    try:
        os.chmod(path, 0o555, follow_symlinks=False)
        if hostdenial.privileged():
            os.chown(path, 0, 0, follow_symlinks=False)
    except (OSError, NotImplementedError):
        return _unknown(path, "could not be written")
    if not _still_empty_dir(path):
        return _occupied(path)
    if not hostdenial.set_immutable(path):
        return _unknown(path, "could not be verified")
    held = hostdenial.held_by(path)
    if held == hostdenial.ROOT_HELD:
        return PathOutcome(path, ENFORCING, _ROOT_DETAIL)
    if held == hostdenial.SELF_HELD:
        return PathOutcome(path, SELF_ENFORCING, _SELF_DETAIL)
    return _unknown(path, "could not be verified")


def remove_one(path: Path) -> PathOutcome:
    """Take back a denial this tool placed, and nothing else.

    What it will remove is decided by SHAPE, the same way a denial is recognised: an empty
    directory nothing can write into, at a location this tool targets. That is deliberately not
    "unlock what I am pointed at" — a location holding someone's content, or a lock at a path this
    does not target, is not this command's to open. The removal is read back; a directory still
    there afterwards is never reported as gone.
    """
    held = hostdenial.held_by(path)
    if held is None:
        return PathOutcome(path, NOTHING_TO_REMOVE, "no control of this tool's here")
    if held == hostdenial.ROOT_HELD and not hostdenial.privileged():
        return PathOutcome(path, NEEDS_ROOT,
                           "root holds this one — run again with sudo to take it back")
    if not hostdenial.clear_immutable(path):
        return _unknown(path, "the lock could not be taken off")
    if not hostdenial.empty_dir(path):
        hostdenial.set_immutable(path)
        return _occupied(path)
    try:
        os.rmdir(path)
    except OSError:
        hostdenial.set_immutable(path)
        return _unknown(path, "could not be removed")
    if path.exists():
        return _unknown(path, "could not be verified")
    return PathOutcome(path, REMOVED, "taken back")
