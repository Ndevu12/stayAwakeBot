#!/usr/bin/env python3
"""Find a program the operating system ships, by absolute path and never through PATH."""
from __future__ import annotations

import os
import stat as _stat


def system_binary(candidates, *, stat=os.stat, access=os.access) -> str | None:
    """Find the first program in `candidates` that the system owns. Takes absolute paths in order of
    preference. Returns the first one that is a regular executable file owned by root and writable
    by no one else, or None when there is none."""
    for candidate in candidates:
        if not os.path.isabs(candidate):
            continue
        try:
            st = stat(candidate)
        except OSError:
            continue
        if (_stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
                and access(candidate, os.X_OK)):
            return candidate
    return None
