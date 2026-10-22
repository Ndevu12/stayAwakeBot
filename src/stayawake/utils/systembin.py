#!/usr/bin/env python3
"""Find a program the operating system ships, by absolute path and never through PATH."""
from __future__ import annotations

import ctypes
import os
import stat as _stat
import sys


def windows_system_root() -> str:
    """Name the Windows system directory's parent. Returns it, or `C:\\Windows` when this is not
    Windows or the directory cannot be read."""
    if sys.platform.startswith("win"):
        try:
            buf = ctypes.create_unicode_buffer(260)
            if ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260):
                parent = os.path.dirname(buf.value)
                if parent:
                    return parent
        except (AttributeError, OSError):
            pass
    return r"C:\Windows"


def in_windows_system_directory(candidate: str, root: str) -> bool:
    """Tell whether `candidate` is a file the Windows system directory holds. Takes the path and the
    system root. Returns the answer."""
    text = candidate.replace("/", "\\")
    if ".." in text.split("\\"):
        return False
    base = root.replace("/", "\\").rstrip("\\")
    lowered = text.casefold()
    for folder in ("System32", "SysWOW64"):
        prefix = f"{base}\\{folder}\\".casefold()
        if lowered.startswith(prefix) and lowered[len(prefix):]:
            return True
    return False


def system_binary(candidates, *, stat=os.stat, access=os.access) -> str | None:
    """Find the first program in `candidates` that the system owns. Takes absolute paths in order of
    preference. Returns the first regular executable the operating system provides, or None when
    there is none."""
    windows = sys.platform.startswith("win")
    root = windows_system_root()
    for candidate in candidates:
        if windows:
            if not in_windows_system_directory(candidate, root):
                continue
        elif not os.path.isabs(candidate):
            continue
        try:
            st = stat(candidate)
        except OSError:
            continue
        if not _stat.S_ISREG(st.st_mode) or not access(candidate, os.X_OK):
            continue
        if windows or (st.st_uid == 0 and not st.st_mode & 0o022):
            return candidate
    return None
