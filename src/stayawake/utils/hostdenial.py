#!/usr/bin/env python3
"""Whether a host-level denial is in place — read-back, never the write."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

_UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)


def privileged() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def platform_supported() -> bool:
    return sys.platform in ("darwin", "linux")


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
        try:
            r = subprocess.run(["lsattr", "-d", "--", str(path)],
                               capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        if r.returncode != 0 or not r.stdout.split():
            return False
        return "i" in r.stdout.split()[0]
    return False


def holds(path: Path) -> bool:
    """True only when a read-back shows a root-owned immutable empty directory."""
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    if st.st_uid != 0:
        return False
    return immutable(path) and empty_dir(path)


def set_immutable(path: Path) -> bool:
    if sys.platform == "darwin":
        try:
            flags = path.lstat().st_flags
            os.chflags(path, flags | _UF_IMMUTABLE)
            return immutable(path)
        except OSError:
            return False
    if sys.platform == "linux":
        try:
            r = subprocess.run(["chattr", "+i", "--", str(path)],
                               capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        return r.returncode == 0 and immutable(path)
    return False
