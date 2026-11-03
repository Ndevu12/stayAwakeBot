#!/usr/bin/env python3
"""Read the files a repository holds when it has no working tree."""
from __future__ import annotations

import os
from pathlib import Path

_BLOB_MODES = frozenset({b"100644", b"100755"})
_SKIPPED_MODES = frozenset({b"120000", b"160000"})
_UNREAD = "HEAD: the files this repository holds could not be listed"


def looks_like_a_git_directory(path: Path) -> bool:
    """Whether this directory has the entries a git directory has. Takes the directory. Returns
    True when HEAD, objects and refs are all present."""
    try:
        return ((path / "HEAD").is_file() and (path / "objects").is_dir()
                and (path / "refs").is_dir())
    except OSError:
        return False


def files_held(root: Path, excluded: set[str]) -> tuple[dict[str, str], str | None]:
    """List the files HEAD holds. Takes the repository and directory names to leave out. Returns
    each path with its object id, and an error when the list could not be read. An empty
    repository returns an empty map and no error."""
    from stayawake.lib.git.run import answer, stdout_bytes

    commits = answer(root, ["rev-list", "--max-count=1", "--all"])
    if commits is None:
        return {}, _UNREAD
    if commits.strip() == "":
        return {}, None
    raw = stdout_bytes(root, ["ls-tree", "-r", "-z", "HEAD"])
    if raw is None:
        return {}, _UNREAD
    files: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, sep, path = record.partition(b"\t")
        bits = meta.split(b" ")
        if not sep or len(bits) != 3:
            return {}, _UNREAD
        mode, _kind, sha = bits
        if mode in _SKIPPED_MODES:
            continue
        if mode not in _BLOB_MODES:
            return {}, _UNREAD
        rel = os.fsdecode(path)
        if any(part in excluded for part in rel.split("/")[:-1]):
            continue
        files[rel] = sha.decode("ascii")
    return files, None


def object_size(root: Path, oid: str) -> int | None:
    """The size of one stored object. Takes the repository and the object id. Returns the size in
    bytes, or None when git could not answer."""
    from stayawake.lib.git.run import answer

    sized = answer(root, ["cat-file", "-s", oid])
    if sized is None:
        return None
    text = sized.strip()
    return int(text) if text.isascii() and text.isdigit() else None
