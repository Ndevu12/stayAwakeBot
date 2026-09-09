#!/usr/bin/env python3
"""Replace a file's contents in one step, or not at all."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def replace(where: Path, text: str, *, mode: int = 0o600) -> bool:
    """Write `text` to `where` atomically. True only when a read-back returns what was written.

    TRAP: a symlinked destination is refused, the staging name is unpredictable, and the read-back
    compares against what was written rather than against a re-derived expectation. Newlines are
    written exactly as given, so correcting one setting never rewrites every line of the file.
    """
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
    try:
        with open(where, encoding="utf-8", newline="") as handle:
            return handle.read() == text
    except OSError:
        return False
