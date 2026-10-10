#!/usr/bin/env python3
"""Replace a file's contents in one step, or not at all."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from stayawake.utils import pathsafe


def replace(where: Path, text: str, *, mode: int = 0o600) -> bool:
    """Write `text` to `where` atomically. True only when a read-back, which never follows a link
    or waits on anything that is not a file, returns exactly what was written."""
    try:
        if where.is_symlink():
            return False
        where.parent.mkdir(parents=True, exist_ok=True)
        fd, staged = tempfile.mkstemp(dir=str(where.parent), prefix=".saw-", suffix=where.suffix)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
            os.chmod(staged, mode)
            os.replace(staged, where)
        finally:
            if os.path.exists(staged):
                os.unlink(staged)
    except OSError:
        return False
    written = text.encode("utf-8")
    return pathsafe.read_regular_no_follow(where, len(written)) == written
