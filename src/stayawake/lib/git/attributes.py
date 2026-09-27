#!/usr/bin/env python3
"""A working tree's `.gitattributes`, carried as data into one `info/attributes` file of a
repository saw owns."""
from __future__ import annotations

import os
import stat
from pathlib import Path

ATTRIBUTES_FILE = ".gitattributes"
_MAX_ATTRIBUTES_BYTES = 1 << 20


def read_regular(path: Path, limit: int = _MAX_ATTRIBUTES_BYTES) -> bytes | None:
    """The bytes of `path` when it is a regular file within `limit`, without following a link.
    Returns None otherwise."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(limit + 1)[:limit]
    except OSError:
        return None
    finally:
        os.close(fd)


def _rooted(directory: str, line: bytes) -> bytes | None:
    """One line of `directory`'s `.gitattributes`, rewritten to match from the repository root.
    Returns None for a line that has no meaning outside the root file."""
    stripped = line.strip()
    if not stripped or stripped.startswith(b"#"):
        return None
    if not directory:
        return stripped
    if stripped.startswith(b"[attr]") or stripped.startswith(b'"'):
        return None
    pattern, _, rest = stripped.partition(b" ")
    if b"\t" in pattern:
        pattern, _, tail = pattern.partition(b"\t")
        rest = tail + (b" " + rest if rest else b"")
    base = directory.encode("utf-8", "surrogateescape")
    if pattern.startswith(b"/"):
        rooted = base + pattern
    elif b"/" in pattern.rstrip(b"/"):
        rooted = base + b"/" + pattern
    else:
        rooted = base + b"/**/" + pattern
    return rooted + (b" " + rest if rest else b"")


def carried(worktree: Path | None, tracked_paths: list[str], info_attributes: bytes | None) -> bytes:
    """The one attributes file equivalent to a working tree's. Takes the working tree (None for a
    bare repository), the tracked paths and the repository's own `info/attributes`. Returns its
    bytes: the root file, then deeper files shallowest first, then `info/attributes`, so later lines
    win as git's precedence has them do."""
    lines: list[bytes] = []
    if worktree is not None:
        files = [p for p in tracked_paths
                 if p == ATTRIBUTES_FILE or p.endswith("/" + ATTRIBUTES_FILE)]
        for rel in sorted(files, key=lambda p: (p.count("/"), p)):
            data = read_regular(worktree / rel)
            if data is None:
                continue
            directory = rel[:-len(ATTRIBUTES_FILE)].rstrip("/")
            lines += [out for out in (_rooted(directory, ln) for ln in data.splitlines()) if out]
    if info_attributes:
        lines += [ln.strip() for ln in info_attributes.splitlines() if ln.strip()]
    return b"\n".join(lines) + (b"\n" if lines else b"")
