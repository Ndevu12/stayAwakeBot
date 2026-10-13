#!/usr/bin/env python3
"""Ask for privilege for one action, rather than requiring it for a whole command."""
from __future__ import annotations

import os
import stat
import subprocess

from stayawake.utils.streaming import spinners_held

_SUDO_PATHS = ("/usr/bin/sudo", "/bin/sudo")
_TIMEOUT = 120
_ADMINISTRATOR_GROUPS = frozenset({"wheel", "sudo", "admin"})

NOT_AVAILABLE = "not-available"     # no trustworthy sudo on this machine
CANNOT_ASK = "cannot-ask"           # permission is needed and there is nobody for the system to ask
NOT_AN_ADMINISTRATOR = "not-an-administrator"
DECLINED = "declined"               # asked, and not granted
GRANTED = "granted"                 # the command ran as root


def trusted_sudo() -> str | None:
    """An absolute `sudo` owned by root that no one else can write to, or None."""
    for candidate in _SUDO_PATHS:
        try:
            info = os.stat(candidate)
        except OSError:
            continue
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            continue
        if not info.st_mode & stat.S_ISUID:
            continue
        return candidate
    return None


def can_ask(*, terminal=None) -> bool:
    """Whether there is a terminal the system can ask for permission on."""
    if terminal is not None:
        try:
            return bool(terminal())
        except OSError:
            return False
    try:
        handle = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return False
    os.close(handle)
    return True


def may_use_sudo(*, groups=None) -> bool:
    """Tell whether this account administers the machine. Takes the account's group names, read
    from the system when None. Returns True when it does."""
    names = _group_names() if groups is None else set(groups)
    return bool(names & _ADMINISTRATOR_GROUPS)


def _group_names() -> set[str]:
    """Name the groups this account belongs to. Returns their names, or none when they cannot be
    read."""
    try:
        import grp
    except ImportError:
        return set()
    names = set()
    for gid in {*os.getgroups(), os.getgid()}:
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except (KeyError, OverflowError):
            continue
    return names


def run_as_root(argv: list[str], *, sudo=trusted_sudo, ask=can_ask, admin=may_use_sudo,
                run=subprocess.run, quiet_spinners=spinners_held) -> tuple[str, str]:
    """Run `argv` as root, leaving it to the system's own prompt to ask for permission when it
    must. Takes the command and the collaborators that find sudo, tell whether there is someone to
    ask and whether they administer the machine, run a command, and keep spinners off the
    terminal. Returns `(outcome, detail)`."""
    binary = sudo()
    if binary is None:
        return NOT_AVAILABLE, "no trustworthy sudo was found on this machine"
    quiet = [binary, "-n", "--", *argv]
    try:
        done = run(quiet, capture_output=True, text=True, timeout=_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return NOT_AVAILABLE, f"{type(exc).__name__}: {exc}"
    if done.returncode == 0:
        return GRANTED, "already granted"
    if not admin():
        return NOT_AN_ADMINISTRATOR, "this account does not administer the machine"
    if not ask():
        return CANNOT_ASK, "permission is needed and there is no terminal for the system to ask on"
    try:
        with quiet_spinners():
            asked = run([binary, "--", *argv], timeout=_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return DECLINED, f"{type(exc).__name__}: {exc}"
    return (GRANTED, "granted") if asked.returncode == 0 else (DECLINED, "not granted")
