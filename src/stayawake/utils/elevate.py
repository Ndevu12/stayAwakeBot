#!/usr/bin/env python3
"""Ask for privilege for one action, rather than requiring it for a whole command."""
from __future__ import annotations

import os
import stat
import subprocess
import sys

_SUDO_PATHS = ("/usr/bin/sudo", "/bin/sudo")
_TIMEOUT = 120

#: What asking for privilege did.
NOT_AVAILABLE = "not-available"     # no trustworthy sudo on this machine
CANNOT_ASK = "cannot-ask"           # it needs a password and there is nobody to ask
DECLINED = "declined"               # asked, and not granted
GRANTED = "granted"                 # the command ran as root


def trusted_sudo() -> str | None:
    """An absolute `sudo` owned by root that no one else can write to, or None.

    TRAP: never resolved through `PATH`. This runs on a machine assumed to be compromised.
    """
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


def can_ask(*, isatty=None) -> bool:
    """Whether there is somebody present to answer a password prompt."""
    check = isatty or (lambda: sys.stdin.isatty() and sys.stderr.isatty())
    try:
        return bool(check())
    except (OSError, ValueError):
        return False


def run_as_root(argv: list[str], *, sudo=trusted_sudo, ask=can_ask,
                run=subprocess.run) -> tuple[str, str]:
    """Run `argv` as root, asking only where asking is possible. Returns `(outcome, detail)`.

    TRAP: `argv` is a list, never a string — it carries attacker-chosen values.
    """
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
    if not ask():
        return CANNOT_ASK, "it needs a password and there is no terminal to ask on"
    try:
        asked = run([binary, "--", *argv], timeout=_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return DECLINED, f"{type(exc).__name__}: {exc}"
    return (GRANTED, "granted") if asked.returncode == 0 else (DECLINED, "not granted")
