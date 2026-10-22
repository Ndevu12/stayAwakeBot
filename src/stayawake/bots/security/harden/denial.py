#!/usr/bin/env python3
"""Create one host-level denial, then read it back."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, replace
from pathlib import Path

from stayawake.utils import hostdenial
from stayawake.utils.pathsafe import directory_flag, no_follow_flag, trusted_ancestor

from stayawake.bots.security.hygiene import staging_kit

from . import hold_aside, remove_kit


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
_MOVE_NEEDS_ROOT_DETAIL = ("something is where this control goes, and only an administrator can move it "
                           "aside and lock the control here — run again with sudo")
_LOCK_NEEDS_ROOT_DETAIL = ("only an administrator can lock a folder on this system — run again with "
                           "sudo; nothing was left in its place")
_SELF_DETAIL = ("in place; anything running as you can remove it — run again with sudo to make it "
                "root-owned")


@dataclass(frozen=True)
class PathOutcome:
    path: Path
    state: str
    detail: str
    moved_aside: bool = False
    put_back: str = ""
    kit: str = ""


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
        if not trusted_ancestor(ancestor):
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
        _chown(path, 0, 0)
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
        _chown(path, owner, -1)
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


def _hand_back_what_was_made(path: Path, owner: int, failure: str,
                             made: int | None) -> tuple[PathOutcome, bool]:
    """Undo what this run changed at `path` as `_hand_back` does, then remove the folder this run
    created there while it is still that folder and still empty. Takes the location, its owner
    before, the reason, and an open descriptor on the folder made there (None when it was there
    before). Returns the outcome and whether the folder was removed."""
    handed = _hand_back(path, owner, failure)
    if handed.state != UNKNOWN or made is None or not _remove_what_was_made(path, made):
        return handed, False
    return _unknown(path, f"{failure}; the folder this run created was removed"), True


def _remove_what_was_made(path: Path, made: int) -> bool:
    """Remove the folder this run created at `path`. Takes the location and an open descriptor on the
    folder made there, which keeps its inode from being given to anything else. Returns True when it
    was that folder, unlocked and empty, and is gone; anything else there, or anything put in it, is
    left."""
    try:
        st = path.lstat()
        held = os.fstat(made)
    except OSError:
        return False
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
            or (st.st_dev, st.st_ino) != (held.st_dev, held.st_ino)):
        return False
    if hostdenial.immutable(path) or not hostdenial.empty_dir(path):
        return False
    try:
        os.rmdir(path)
    except OSError:
        return False
    return not os.path.lexists(path)


def _held_open(path: Path) -> int | None:
    """Open the folder this run just created at `path` and hold it. Takes the location. Returns the
    descriptor, which the caller closes, or None when it cannot be opened as a folder."""
    try:
        return os.open(path, os.O_RDONLY | directory_flag() | no_follow_flag())
    except OSError:
        return None


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


def _chown(path: Path, uid: int, gid: int) -> None:
    """Give `path` to `uid`. Takes the path and the account. Raises OSError when it cannot."""
    try:
        os.chown(path, uid, gid, follow_symlinks=False)
    except AttributeError:
        if uid != 0 or not hostdenial.give_to_root(path):
            raise OSError(0, "could not be given to an administrator")


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
    """Place the denial at `path`: where something is already there, move it aside beside the
    location first; never remove it. Takes the location. Returns what was done."""
    outcome = _apply(path, may_move=True)
    if outcome.kit == KIT_LEFT:
        return outcome
    beside = _remove_kits_beside(path)
    if not beside:
        return outcome
    return replace(outcome, kit=KIT_LEFT if beside == KIT_LEFT else KIT_REMOVED)


def _remove_kits_beside(path: Path) -> str:
    """Delete every known worm's staging kit saw had moved aside, or was removing, beside `path`.
    Takes the location. Returns KIT_LEFT when one could not be fully removed, KIT_REMOVED when one
    was, and "" when there was none."""
    from .live import capture_path
    try:
        beside = [*staging_kit.held_aside(path), *staging_kit.being_removed(path)]
    except OSError:
        return ""
    found = ""
    for entry in beside:
        if not _is_the_kit(entry):
            continue
        removal = remove_kit.remove(entry, capture_path(), named_for=path)
        if removal.left is not None or removal.mismatch:
            found = KIT_LEFT
        elif removal.removed and found != KIT_LEFT:
            found = KIT_REMOVED
    return found


def _apply(path: Path, *, may_move: bool) -> PathOutcome:
    """Create the denial at `path` if the location is free, or with `may_move` once what is there
    has been moved aside; never remove what is already there.

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
            return _override(path) if may_move else _occupied(path)
    elif not _create_where_it_was_named(path):
        if not hostdenial.privileged() and not hostdenial.can_write_into(path):
            return PathOutcome(path, NEEDS_ROOT,
                               "this location is not yours to write to — run again with sudo")
        return _unknown(path, "could not be created")
    made = _held_open(path) if st is None else None
    try:
        return _seal(path, made, may_move)
    finally:
        if made is not None:
            os.close(made)


def _seal(path: Path, made: int | None, may_move: bool) -> PathOutcome:
    """Make the empty folder at `path` read-only and lock it, handing back what this run changed when
    either fails. Takes the location, an open descriptor on the folder this run created there (None
    when it was there before) and whether what arrives may still be moved aside. Returns the outcome."""
    owner_before = _owner_of(path)
    try:
        os.chmod(path, 0o555, follow_symlinks=False)
        if hostdenial.privileged():
            _chown(path, 0, 0)
    except (OSError, NotImplementedError):
        return _hand_back_what_was_made(path, owner_before, "could not be written", made)[0]
    if not _still_empty_dir(path):
        return _override_what_arrived(path, _hand_back(path, owner_before), may_move)
    if not _sealed_over_nothing(path):
        handed, removed = _hand_back_what_was_made(path, owner_before, "could not be verified", made)
        if removed and hostdenial.lock_needs_privilege() and not hostdenial.privileged():
            return PathOutcome(path, NEEDS_ROOT, _LOCK_NEEDS_ROOT_DETAIL)
        return _override_what_arrived(path, handed, may_move)
    held = hostdenial.held_by(path)
    if held == hostdenial.ROOT_HELD:
        return PathOutcome(path, ENFORCING, _ROOT_DETAIL)
    if held == hostdenial.SELF_HELD:
        return PathOutcome(path, SELF_ENFORCING, _SELF_DETAIL)
    return _hand_back_what_was_made(path, owner_before, "could not be verified", made)[0]


_PLACED = frozenset({ENFORCING, SELF_ENFORCING})
KIT_REMOVED, KIT_LEFT = "removed", "left"


def _is_the_kit(path: Path) -> bool:
    """Tell whether what is at `path` is the known worm's staging kit. Takes the location. Returns
    False for anything this cannot tell, so nothing it cannot recognise is deleted."""
    try:
        return staging_kit.holds_a_kit(path)
    except OSError:
        return False


def _remove_the_kit(path: Path) -> PathOutcome | None:
    """Delete the known worm's staging kit at `path` and place the denial there. Takes the location.
    Returns the outcome, or None when it is not the kit to delete."""
    from .live import capture_path
    removal = remove_kit.remove(path, capture_path())
    if removal.mismatch:
        return _unknown(path, "what was here changed while saw removed it, so it was put back and no "
                              "control was placed")
    if removal.left is not None:
        return PathOutcome(path, UNKNOWN, "a known worm's staging kit could not be fully removed", kit=KIT_LEFT)
    if not removal.removed:
        return None
    return replace(_apply(path, may_move=False), kit=KIT_REMOVED)


def _override_what_arrived(path: Path, handed: PathOutcome, may_move: bool) -> PathOutcome:
    """Move aside what arrived while the location was open, and place the denial once more. Takes the
    location, what handing it back found and whether a move is still allowed. Returns the outcome."""
    if handed.state == LEFT_OPEN_OVER_CONTENT and may_move:
        return _override(path)
    return handed


def _override(path: Path) -> PathOutcome:
    """Move what is at `path` aside, beside it, and place the denial there; put it back when the
    denial could not be placed. Takes the location. Returns the outcome: placed, for an
    administrator, or the reason neither could be done."""
    if _is_the_kit(path):
        removed = _remove_the_kit(path)
        if removed is not None:
            return removed
    if hostdenial.lock_needs_privilege() and not hostdenial.privileged():
        return PathOutcome(path, NEEDS_ROOT, _MOVE_NEEDS_ROOT_DETAIL)
    held = hold_aside.hold(path)
    if held is None:
        return _unknown(path, "could not be read")
    try:
        return _move_and_place(path, held)
    finally:
        held.close()


def _move_and_place(path: Path, held: hold_aside.Held) -> PathOutcome:
    """Move what is held at `path` aside and place the denial there; put it back when the denial could
    not be placed. Takes the location and what is held there. Returns the outcome."""
    seen = held.seen
    moved = hold_aside.move_aside(path, held)
    if moved.mismatch:
        return _unknown(path, "what was here changed while saw moved it, so it was put back and no "
                              "control was placed")
    if moved.held is None:
        if not hostdenial.privileged():
            return PathOutcome(path, NEEDS_ROOT, _MOVE_NEEDS_ROOT_DETAIL)
        return _occupied(path)
    placed = _apply(path, may_move=False)
    if placed.state in _PLACED:
        return replace(placed, moved_aside=True)
    if hold_aside.put_back_this(path, moved.held, seen):
        return placed
    return PathOutcome(path, UNKNOWN, "saw moved what was here aside, could not place the control and "
                                      "could not put it back, so it is still beside where it was",
                       moved_aside=True)


_NOT_THERE, _UNREADABLE, _LEADS_ELSEWHERE, _CLEAR = "not-there", "unreadable", "elsewhere", "clear"


def _on_the_way_to(path: Path) -> str:
    """Judge every folder on the way to a location without following links. Takes the location.
    Returns whether one is not there, cannot be read, leads somewhere else, or all are clear."""
    for folder in reversed(path.parents):
        try:
            found = os.lstat(folder)
        except (FileNotFoundError, NotADirectoryError):
            return _NOT_THERE
        except OSError:
            return _UNREADABLE
        if not stat.S_ISLNK(found.st_mode) and not stat.S_ISDIR(found.st_mode):
            return _NOT_THERE
        if not trusted_ancestor(folder):
            return _LEADS_ELSEWHERE
    return _CLEAR


def _unreadable(path: Path) -> PathOutcome:
    """Say that a location could not be read. Takes the location. Returns its outcome: one an
    administrator can take back, or one that could not be taken back when this run is root."""
    if hostdenial.privileged():
        return _unknown(path, "could not be read")
    return PathOutcome(path, NEEDS_ROOT, "could not be read")


def remove_one(path: Path, *, keeps_aside=None) -> PathOutcome:
    """Take back the denial at `path`, then put back what saw moved aside to place it, while the
    location is free and it is not something to keep aside. Takes the location and
    `keeps_aside(held) -> bool` (default: the known staging kit stays aside). Returns the outcome."""
    outcome = _remove_denial(path)
    if outcome.state not in (REMOVED, NOTHING_TO_REMOVE):
        return outcome
    back = hold_aside.put_back(path, keeps_aside or _stays_aside)
    return outcome if back == hold_aside.NOTHING_HELD else replace(outcome, put_back=back)


def _stays_aside(held: Path) -> bool:
    """Tell whether something saw moved aside must stay aside: the known staging kit, or a link to one.
    Takes where it is held. Returns True for either, and for anything this cannot tell; raises
    OSError when what a link leads to cannot be read."""
    if os.path.islink(held):
        return staging_kit.holds_a_kit(Path(os.path.realpath(held)))
    return staging_kit.holds_a_kit(held)


def _remove_denial(path: Path) -> PathOutcome:
    """Take back a denial this tool placed, and nothing else.

    What it will remove is decided by SHAPE, the same way a denial is recognised: an empty
    directory nothing can write into, at a location this tool targets. That is deliberately not
    "unlock what I am pointed at" — a location holding someone's content, or a lock at a path this
    does not target, is not this command's to open. The removal is read back; a directory still
    there afterwards is never reported as gone.
    """
    on_the_way = _on_the_way_to(path)
    if on_the_way == _NOT_THERE:
        return PathOutcome(path, NOTHING_TO_REMOVE, "not on this machine")
    if on_the_way == _UNREADABLE:
        return _unreadable(path)
    if on_the_way == _LEADS_ELSEWHERE:
        return PathOutcome(path, NOT_WHERE_IT_WAS_NAMED,
                           "a link on the way to it points somewhere else, so it was left as it is")
    try:
        found = os.lstat(path)
    except FileNotFoundError:
        return PathOutcome(path, NOTHING_TO_REMOVE, "nothing of saw's here")
    except OSError:
        return _unreadable(path)
    held = hostdenial.held_by(path)
    if held is None:
        if hostdenial.immutable(path):
            return PathOutcome(path, LOCKED_OVER_CONTENT,
                               "it is locked and holds files saw did not put there, so it was left "
                               "locked. Run `saw audit` before anything else")
        if not stat.S_ISDIR(found.st_mode) or not hostdenial.empty_dir(path):
            return PathOutcome(path, OCCUPIED, "something saw did not put there is here")
        return PathOutcome(path, NOTHING_TO_REMOVE, "nothing of saw's here")
    if held == hostdenial.OTHER_HELD:
        return PathOutcome(path, HELD_BY_ANOTHER,
                           "another account placed this one, so it was left as it is")
    if held == hostdenial.ROOT_HELD and not hostdenial.privileged():
        return PathOutcome(path, NEEDS_ROOT,
                           "an administrator placed this one. Run `sudo saw harden --take-back` "
                           "to take it back")
    if not hostdenial.clear_immutable(path):
        return _unknown(path, "the lock could not be taken off")
    if not hostdenial.empty_dir(path):
        return PathOutcome(path, LEFT_OPEN_OVER_CONTENT,
                           "files arrived while it was unlocked, so it was left unlocked for you "
                           "to read them. Run `saw audit`")
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
