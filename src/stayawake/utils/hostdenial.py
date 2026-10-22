#!/usr/bin/env python3
"""Whether a host-level denial is in place — read-back, never the write."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

from stayawake.utils import operator, winlock
from stayawake.utils.host import saw_runs_here

_UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)

_ATTR_TOOL_ABSOLUTE_PATHS = {
    "lsattr": ("/usr/bin/lsattr", "/bin/lsattr", "/usr/sbin/lsattr"),
    "chattr": ("/usr/bin/chattr", "/bin/chattr", "/usr/sbin/chattr"),
}


def _attr_tool(name: str) -> str | None:
    """Where `name` is, or None when it is not anywhere this will look.

    Never through `PATH`: this runs unprivileged, so a program earlier in it that prints a flags
    field containing `i` would make an unlocked directory read back as locked. None is not
    "not locked" and never reaches success.
    """
    for candidate in _ATTR_TOOL_ABSOLUTE_PATHS[name]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def privileged() -> bool:
    """Tell whether this process is the machine's administrator. Returns the answer."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None:
        return geteuid() == 0
    return winlock.administrator()


def platform_supported() -> bool:
    """Tell whether a denial can be placed on this system. Returns the answer."""
    return saw_runs_here()


def give_to_root(path: Path) -> bool:
    """Make the machine's administrator the owner of `path`. Takes the path. Returns whether a
    read-back shows that owner."""
    if not sys.platform.startswith("win"):
        return False
    return winlock.give_to_administrators(path)


def lock_needs_privilege() -> bool:
    """Tell whether only an administrator can set the immutable flag here. Returns True on Linux,
    where setting it needs CAP_LINUX_IMMUTABLE, and False on macOS, where a folder's owner can."""
    return sys.platform == "linux"


def empty_dir(path: Path) -> bool:
    try:
        next(path.iterdir())
    except StopIteration:
        return True
    except OSError:
        return False
    return False


def immutable(path: Path) -> bool:
    if sys.platform == "darwin":
        try:
            return bool(path.lstat().st_flags & _UF_IMMUTABLE)
        except (OSError, AttributeError):
            return False
    if sys.platform == "linux":
        tool = _attr_tool("lsattr")
        if tool is None:
            return False
        try:
            r = subprocess.run([tool, "-d", "--", str(path)],
                               capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        if r.returncode != 0 or not r.stdout.split():
            return False
        flags = r.stdout.split()[0]
        if not flags or not all(c.isalpha() or c == "-" for c in flags):
            return False
        return "i" in flags
    if sys.platform.startswith("win"):
        sid = winlock.current_sid()
        return sid is not None and winlock.write_denied(path, sid)
    return False


ROOT_HELD = "root"
SELF_HELD = "self"
OTHER_HELD = "other"


def held_by(path: Path) -> str | None:
    """Who holds the denial at `path`, or None when nothing does.

    `root` is the durable form: an immutable empty directory root owns, which code running as the
    operator cannot unlock. `self` is the same lock owned by the operator — MEASURED, its owner
    clears the flag with one call and no privilege, so it is a weaker control and the caller must
    never report the two as the same thing.

    Both are worth setting. An unguarded write to either throws and takes the writing process with
    it; only the second can be undone by whatever it was set against.

    `other` is the same lock under a third account — answering None there sent the caller into a
    write that the flag guarantees will fail. It is also what a mis-resolved account produces, so a
    real control stays visible instead of reading as absent.
    """
    try:
        st = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return None
    if not (immutable(path) and empty_dir(path)):
        return None
    if sys.platform.startswith("win"):
        return winlock.grade(winlock.owner_sid(path), winlock.current_sid())
    if st.st_uid == 0:
        return ROOT_HELD
    if st.st_uid == operator.acting_uid():
        return SELF_HELD
    return OTHER_HELD


def held_by_us(path: Path) -> bool:
    """True when the denial at `path` is this tool's own work, at either grade.

    A control under a third account is not ours, and is graded as it was before that state existed.
    """
    return held_by(path) in (ROOT_HELD, SELF_HELD)


def holds(path: Path) -> bool:
    """True only when a read-back shows a root-owned immutable empty directory.

    The strict form, for the one caller that must not accept a lock the operator can clear: the
    read-back after a control is raised to root.
    """
    return held_by(path) == ROOT_HELD


def can_write_into(path: Path) -> bool:
    """Whether a denial could be created at `path` without raising privilege.

    Asked of the nearest parent that exists, because that is the directory the creation writes
    into. A command that requires root for every path asks for privilege it does not need on
    most of them.
    """
    for candidate in [path] + list(path.parents):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return False
        return os.access(candidate, os.W_OK)
    return False


def clear_immutable(path: Path) -> bool:
    """Take the flag off, so the owner can be changed and the flag put back."""
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    if sys.platform == "darwin":
        try:
            os.chflags(path, st.st_flags & ~_UF_IMMUTABLE, follow_symlinks=False)
            return not immutable(path)
        except (OSError, NotImplementedError):
            return False
    if sys.platform == "linux":
        tool = _attr_tool("chattr")
        if tool is None:
            return False
        try:
            r = subprocess.run([tool, "-i", "--", str(path)],
                               capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        return r.returncode == 0 and not immutable(path)
    if sys.platform.startswith("win"):
        sid = winlock.current_sid()
        return sid is not None and winlock.allow_writes(path, sid)
    return False


def set_immutable(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    if sys.platform == "darwin":
        try:
            flags = st.st_flags
            os.chflags(path, flags | _UF_IMMUTABLE, follow_symlinks=False)
            return immutable(path)
        except (OSError, NotImplementedError):
            return False
    if sys.platform == "linux":
        tool = _attr_tool("chattr")
        if tool is None:
            return False
        try:
            r = subprocess.run([tool, "+i", "--", str(path)],
                               capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        return r.returncode == 0 and immutable(path)
    if sys.platform.startswith("win"):
        sid = winlock.current_sid()
        return sid is not None and winlock.deny_writes(path, sid)
    return False
