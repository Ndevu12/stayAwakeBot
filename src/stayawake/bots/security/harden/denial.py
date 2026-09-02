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
LOCKED_OVER_CONTENT = "locked-over-content"
LEFT_OPEN_OVER_CONTENT = "left-open-over-content"
HELD_BY_ANOTHER = "held-by-another-account"
NOT_WHERE_IT_WAS_NAMED = "not-where-it-was-named"
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
    if held == hostdenial.OTHER_HELD:
        # `chflags(2)`: the owner OR the super-user clears it. Refusing at root asserted a limit
        # nothing read, and left the raise-to-root path unreachable for any lock not ours.
        if hostdenial.privileged():
            return _take_ownership(path)
        return PathOutcome(path, HELD_BY_ANOTHER,
                           "a locked, empty directory here belongs to another account on this "
                           "machine — run again with sudo to take it over")
    return None


def _take_ownership(path: Path) -> PathOutcome:
    """Raise a denial the operator holds to one root holds.

    The flag comes off to change the owner, so the location is briefly open. Every exit that puts
    it back goes through `_sealed_over_nothing`; the version that re-locked directly at two of them
    sealed in whatever arrived and reported a reason that never mentioned it.
    """
    try:
        owner_before = path.lstat().st_uid
    except OSError:
        return _unknown(path, "could not be raised to root")
    if not hostdenial.clear_immutable(path):
        return _unknown(path, "could not be raised to root")
    try:
        os.chown(path, 0, 0, follow_symlinks=False)
    except (OSError, NotImplementedError):
        return _lock_back_over_nothing(path, owner_before, "could not be raised to root")
    if not _sealed_over_nothing(path):
        return _hand_back(path, owner_before)
    if not hostdenial.holds(path):
        return _lock_back_over_nothing(path, owner_before, "could not be verified")
    return PathOutcome(path, ENFORCING, _ROOT_DETAIL)


def _lock_back_over_nothing(path: Path, owner: int, failure: str) -> PathOutcome:
    """Leave the flag on only while the location is still empty; hand it back if it is not."""
    if _sealed_over_nothing(path):
        return _unknown(path, failure)
    return _hand_back(path, owner)


def _sealed_over_nothing(path: Path) -> bool:
    """Set the flag, and answer whether it closed over an empty location.

    THE one place this file sets it. Asking `empty_dir` first and not looking again is two syscalls
    with the race between them, so the answer is a read-back AFTER the write. False means open, and
    does not say why: both reasons leave it open and the caller has to say so either way.
    """
    if not hostdenial.empty_dir(path):
        return False
    if not hostdenial.set_immutable(path):
        return False
    if hostdenial.empty_dir(path):
        return True
    hostdenial.clear_immutable(path)
    return False


def _hand_back(path: Path, owner: int, failure: str | None = None) -> PathOutcome:
    """Undo what this run changed at `path`, and report the state read back afterwards.

    `0o555` denies the write to the OWNER too, so leaving it left the operator unable to remove
    what they were being told to look at. Every sentence below is read back: this is also reached
    after a raise that never changed the owner, where asserting "it is root's now" sent them for
    sudo over a directory already theirs. `failure` is the caller's own reason for being here.
    """
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
        os.chown(path, owner, -1, follow_symlinks=False)
    except (OSError, NotImplementedError):
        pass
    locked = hostdenial.immutable(path)
    empty = hostdenial.empty_dir(path)
    if failure is not None and empty:
        return _unknown(path, failure)
    if locked:
        return PathOutcome(path, LOCKED_OVER_CONTENT,
                           "something is in it and the lock could not be taken off — look at it "
                           "before anything else")
    opening = "something arrived while the lock was off; the lock was NOT put back, so nothing is "
    if _reachable_by(path, owner):
        return PathOutcome(path, LEFT_OPEN_OVER_CONTENT,
                           opening + "sealed in and you can read and remove what is in it")
    return PathOutcome(path, LEFT_OPEN_OVER_CONTENT,
                       opening + "sealed in, but the directory is not yours — read what is in it "
                       "with sudo before anything else")


def _reachable_by(path: Path, owner: int) -> bool:
    """Whether `owner` can now open the directory and remove what is in it.

    Not `os.access`: it answers for the EFFECTIVE uid, and every caller here is root, where it says
    yes to everything. `lstat`, so a link swapped in at the last moment answers for itself.
    """
    try:
        st = path.lstat()
    except OSError:
        return False
    return st.st_uid == owner and bool(st.st_mode & stat.S_IWUSR)


def _owner_of(path: Path) -> int:
    try:
        return path.lstat().st_uid
    except OSError:
        return -1


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

    Everything past the `chmod` changes the location, so every exit past it hands the location back
    rather than leaving it read-only and owned by somebody the operator is not.
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
    owner_before = _owner_of(path)
    try:
        os.chmod(path, 0o555, follow_symlinks=False)
        if hostdenial.privileged():
            os.chown(path, 0, 0, follow_symlinks=False)
    except (OSError, NotImplementedError):
        return _hand_back(path, owner_before, "could not be written")
    if not _still_empty_dir(path):
        return _hand_back(path, owner_before)
    if not _sealed_over_nothing(path):
        return _hand_back(path, owner_before, "could not be verified")
    held = hostdenial.held_by(path)
    if held == hostdenial.ROOT_HELD:
        return PathOutcome(path, ENFORCING, _ROOT_DETAIL)
    if held == hostdenial.SELF_HELD:
        return PathOutcome(path, SELF_ENFORCING, _SELF_DETAIL)
    return _hand_back(path, owner_before, "could not be verified")


def _reached_where_it_was_named(path: Path) -> bool:
    """Whether every step to `path` stays where the caller said.

    The check the creating side makes, for the worse half: removing through a planted link unlocks
    and deletes somewhere unintended. This side had none.
    """
    for ancestor in reversed(path.parents):
        if not _trusted_ancestor(ancestor):
            return False
    return True


def remove_one(path: Path) -> PathOutcome:
    """Take back a denial this tool placed, and nothing else.

    What it will remove is decided by SHAPE, the same way a denial is recognised: an empty
    directory nothing can write into, at a location this tool targets. That is deliberately not
    "unlock what I am pointed at" — a location holding someone's content, or a lock at a path this
    does not target, is not this command's to open. The removal is read back; a directory still
    there afterwards is never reported as gone.
    """
    if not _reached_where_it_was_named(path):
        return PathOutcome(path, NOT_WHERE_IT_WAS_NAMED,
                           "something on the way to this location redirects it elsewhere, so it "
                           "was not opened")
    held = hostdenial.held_by(path)
    if held is None:
        if hostdenial.immutable(path):
            return PathOutcome(path, LOCKED_OVER_CONTENT,
                               "locked, and holding something — this command did not put that "
                               "there and will not open it; look at it before anything else")
        return PathOutcome(path, NOTHING_TO_REMOVE, "no control of this tool's here")
    if held == hostdenial.OTHER_HELD:
        # Without this the removal below would unlock and delete another account's lock.
        return PathOutcome(path, HELD_BY_ANOTHER,
                           "this lock is another account's; this command takes back only what it "
                           "placed, so it was left as it stood")
    if held == hostdenial.ROOT_HELD and not hostdenial.privileged():
        return PathOutcome(path, NEEDS_ROOT,
                           "root holds this one — run again with sudo to take it back")
    if not hostdenial.clear_immutable(path):
        return _unknown(path, "the lock could not be taken off")
    if not hostdenial.empty_dir(path):
        return PathOutcome(path, LEFT_OPEN_OVER_CONTENT,
                           "something arrived while the lock was off; it has been left unlocked "
                           "so you can read and remove what is in it")
    try:
        os.rmdir(path)
    except OSError:
        # Any failure reaches here, not only a non-empty one, so the flag goes back only over an
        # empty location — putting it back unconditionally sealed in whatever had arrived.
        if _sealed_over_nothing(path):
            return _unknown(path, "could not be removed")
        if hostdenial.empty_dir(path):
            return _unknown(path, "could not be removed, and the lock could not be put back")
        return _hand_back(path, _owner_of(path))
    if path.exists():
        return _unknown(path, "could not be verified")
    return PathOutcome(path, REMOVED, "taken back")
