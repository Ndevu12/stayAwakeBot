#!/usr/bin/env python3
"""Copy a git index file with the time git wrote it."""
from __future__ import annotations

import shutil
from pathlib import Path


def copy_index(source: str | Path, target: str | Path) -> None:
    """Copy an index file to `target`, keeping its modification time. Takes the index and where the
    copy goes. Returns nothing. Raises OSError for a failed copy."""
    shutil.copy2(source, target)
