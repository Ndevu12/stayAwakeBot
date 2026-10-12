#!/usr/bin/env python3
"""The contents saw's hook scanned clean at each path of a working tree, so a file checkout that
writes one of them back scans nothing."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from stayawake.bots.security import hookscript
from stayawake.utils import atomicwrite

_VERSION = 1
_LARGEST_STORE = 64 * 1024 * 1024


@dataclass(frozen=True)
class Checked:
    """The files a file checkout leaves to scan, each with its status and content before the scan."""

    files: dict[str, tuple[tuple | None, str | None]]


def store_path(root: Path) -> Path:
    """Name the file that holds a working tree's clean contents. Takes the root. Returns the path."""
    key = hashlib.sha256(os.fsencode(os.path.realpath(root))).hexdigest()[:32]
    return hookscript.clean_contents_dir() / f"{key}.json"


def _status(path: Path) -> tuple | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino, info.st_mode


def held(root: Path, policy: str) -> dict[str, str]:
    """Read the contents scanned clean in a working tree. Takes the root and the digest of the policy
    in force. Returns them by path, or nothing when they were judged under another policy or the
    store cannot be read."""
    raw = atomicwrite.read_back(store_path(root), _LARGEST_STORE)
    if raw is None:
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return {}
    if not isinstance(data, dict) or data.get("version") != _VERSION or data.get("policy") != policy:
        return {}
    clean = data.get("clean")
    if not isinstance(clean, dict) or not all(isinstance(c, str) for c in clean.values()):
        return {}
    return clean


def unknown(root: Path, written: tuple[str, ...], largest: int, policy: str) -> tuple[tuple[str, ...], Checked]:
    """Set aside the written files whose content was scanned clean at the same path. Takes the root,
    the files written, the largest file a scan reads in full and the policy digest. Returns the files
    left to scan and what was seen of them."""
    clean = held(root, policy)
    to_scan, seen = [], {}
    for rel in written:
        path = root / rel
        before = _status(path)
        content = None
        if before is not None and stat.S_ISREG(before[4]):
            content = hookscript.digest_file(path, largest)
        if content is not None and clean.get(rel) == content and _status(path) == before:
            continue
        to_scan.append(rel)
        seen[rel] = (before, content)
    return tuple(to_scan), Checked(seen)


def remember(root: Path, checked: Checked, policy: str) -> bool:
    """Record the contents a clean scan read, each one only when its file did not change while it was
    scanned, and forget the paths no longer on disk. Takes the root, what was seen before the scan
    and the policy digest. Returns True when the store was written."""
    clean = {rel: c for rel, c in held(root, policy).items() if os.path.lexists(root / rel)}
    for rel, (before, content) in checked.files.items():
        if content is not None and before is not None and _status(root / rel) == before:
            clean[rel] = content
    try:
        atomicwrite.make_folder(store_path(root).parent)
    except OSError:
        return False
    return atomicwrite.replace(store_path(root), json.dumps({"version": _VERSION, "policy": policy,
                                                             "clean": clean}))
