#!/usr/bin/env python3
"""Files a test stages by their blobs, and paths too long to open by their full name that git can
still write."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

POSIX_ONLY = "a full path longer than the system allows is a POSIX case"


def too_long_by_its_full_name(folder: Path) -> str:
    """Build a relative path git can write from inside `folder` whose full path there is longer
    than the system opens. Takes the folder, which need not exist yet. Returns the path."""
    existing = next(parent for parent in (folder, *folder.parents) if parent.exists())
    limit = os.pathconf(str(existing), "PC_PATH_MAX")
    parts, left = [], limit - len(str(folder)) + 2
    while left > 0:
        size = min(200, left - 1 if left > 201 else left)
        parts.append("d" * size)
        left -= size + 1
    return "/".join(parts)[:-3] + ".js"


def stage_blob(repo: Path, name: str, text: str, mode: str = "100644") -> None:
    """Stage a file by its blob, writing nothing in the work tree. Takes the repository, the name,
    the text and the mode."""
    blob = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=text,
                          capture_output=True, text=True, check=True).stdout.strip()
    subprocess.run(["git", "-C", str(repo), "update-index", "-z", "--add", "--index-info"],
                   input=b"%s %s\t%s\0" % (mode.encode(), blob.encode(), os.fsencode(name)), check=True, capture_output=True)
