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
        return PathOutcome(path, HELD_BY_ANOTHER,
                           "a locked, empty directory here belongs to another account on this "
                           "machine — this run can neither verify it nor clear it, so it was left "
                           "as it stood")
    return None


def _take_ownership(path: Path) -> PathOutcome:
    """Raise a denial the operator holds to one root holds.

    The flag has to come off to change the owner and go back on afterwards, so this is only worth
    doing with the privilege to finish it — a half-done upgrade leaves the location open.

    Every exit that puts the flag back asks first whether the location is still empty. That is one
    rule with three exits and it was written at one of them, so a run that lost the race AND failed
    sealed the arrival in and reported a reason that never mentioned it.
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
    # The owner cannot be changed while the flag is set, so the location is briefly open. Anything
    # that arrives in that gap must NOT be sealed in: locking it would put content beyond the
    # operator's reach at the exact location this exists to keep empty. Reporting that as
    # "not changed" was false twice over — the lock is off and the owner is now root — and left the
    # arrived file unremovable without sudo, at a location every later run then skipped.
    if not hostdenial.empty_dir(path):
        return _hand_back(path, owner_before)
    if not hostdenial.set_immutable(path):
        return _unknown(path, "could not be verified")
    if not hostdenial.holds(path):
        return _lock_back_over_nothing(path, owner_before, "could not be verified")
    return PathOutcome(path, ENFORCING, _ROOT_DETAIL)


def _lock_back_over_nothing(path: Path, owner: int, failure: str) -> PathOutcome:
    """Leave the flag on only while the location is still empty; hand it back if it is not.

    The read-back that decides this runs after the window, so it also catches an arrival between
    the check above and the write — the flag can be on by the time this is asked, and it comes off
    again rather than staying closed over content.
    """
    if hostdenial.empty_dir(path):
        hostdenial.set_immutable(path)
        return _unknown(path, failure)
    hostdenial.clear_immutable(path)
    return _hand_back(path, owner)


def _hand_back(path: Path, owner: int) -> PathOutcome:
    """Give a location back to the operator after something arrived while its lock was off.

    Both halves of the control come off, not just the flag. `0o555` denies the write to the owner
    as well, so handing the directory back without it leaves the operator unable to delete the file
    that arrived from a directory they own — and MEASURED, that is the state the earlier version
    reported as "not changed". `0o700` rather than what was there before: the location is known to
    be holding something now, and nobody else needs to read it.

    Which of the two things it then says is READ BACK, never assumed from whether the calls threw:
    this is also reached after a failed raise to root, where the owner never changed, and asserting
    "it is root's now" there told the operator to fetch sudo for a directory already their own.
    """
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
        os.chown(path, owner, -1, follow_symlinks=False)
    except (OSError, NotImplementedError):
        pass
    opening = "something arrived while the lock was off; the lock was NOT put back, so nothing is "
    if _reachable_by(path, owner):
        return PathOutcome(path, LEFT_OPEN_OVER_CONTENT,
                           opening + "sealed in and you can read and remove what is in it")
    return PathOutcome(path, LEFT_OPEN_OVER_CONTENT,
                       opening + "sealed in, but the directory is not yours — read what is in it "
                       "with sudo before anything else")


def _reachable_by(path: Path, owner: int) -> bool:
    """Whether `owner` can now open the directory and remove what is in it.

    Asked of the filesystem rather than of `os.access`, which answers for the EFFECTIVE uid — and
    every caller here is running as root, where it says yes to everything.
    """
    try:
        st = path.stat()
    except OSError:
        return False
    return st.st_uid == owner and bool(st.st_mode & stat.S_IWUSR)


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


def _reached_where_it_was_named(path: Path) -> bool:
    """Whether every step to `path` stays where the caller said.

    The same check the creating side makes, for the same reason: a link anyone could have planted
    on the way redirects what follows. Creating through one puts a denial somewhere unintended;
    REMOVING through one unlocks and deletes somewhere unintended, which is the worse half, and it
    had no check at all.
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
        # Before this grade existed the answer here was None, which reached the refusal above only
        # because the directory is immutable. Reaching the removal instead would unlock and delete
        # another account's lock — the "unlock what I am pointed at" verb this must never be.
        return PathOutcome(path, HELD_BY_ANOTHER,
                           "this lock is another account's, not this tool's to take back")
    if held == hostdenial.ROOT_HELD and not hostdenial.privileged():
        return PathOutcome(path, NEEDS_ROOT,
                           "root holds this one — run again with sudo to take it back")
    if not hostdenial.clear_immutable(path):
        return _unknown(path, "the lock could not be taken off")
    if not hostdenial.empty_dir(path):
        # Something arrived while the lock was off. Locking it back would seal it in, which is
        # what the sibling that raises a control refuses to do for the same window — content at
        # this location put beyond the operator's reach is worse than a location left open.
        return PathOutcome(path, LEFT_OPEN_OVER_CONTENT,
                           "something arrived while the lock was off; it has been left unlocked "
                           "so you can read and remove what is in it")
    try:
        os.rmdir(path)
    except OSError:
        if not hostdenial.set_immutable(path):
            return _unknown(path, "could not be removed, and the lock could not be put back")
        return _unknown(path, "could not be removed")
    if path.exists():
        return _unknown(path, "could not be verified")
    return PathOutcome(path, REMOVED, "taken back")
