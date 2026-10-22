"""Name a folder so a later question can tell that it is the same one."""
from __future__ import annotations

import hashlib
import os
import stat


def _digest(rows: list[str]) -> str:
    """Name these rows. Takes them. Returns the name."""
    digest = hashlib.sha256()
    for row in rows:
        digest.update(row.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
    return digest.hexdigest()


def _file_row(root: str, path: str, info: os.stat_result) -> str:
    """Name one file under `root`. Takes the root, the file and its status. Returns the name."""
    return f"file\0{os.path.relpath(path, root)}\0{info.st_size}\0{info.st_mtime_ns}"


def _dir_row(root: str, path: str, info: os.stat_result) -> str:
    """Name one folder under `root`. Takes the root, the folder and its status. Returns the name."""
    return f"dir\0{os.path.relpath(path, root)}\0{info.st_mtime_ns}"


def tree_identity(path: str) -> str | None:
    """Name a file or a folder. Takes the path. Returns the name, or None when it cannot be named."""
    if not isinstance(path, str) or path == "":
        return None
    root = os.path.abspath(os.path.expanduser(path))
    try:
        info = os.lstat(root)
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode):
        return None
    if stat.S_ISREG(info.st_mode):
        return _digest([_file_row(root, root, info)])
    if not stat.S_ISDIR(info.st_mode):
        return None
    rows = [_dir_row(root, root, info)]
    failed = False

    def onerror(_err: OSError) -> None:
        nonlocal failed
        failed = True

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        if failed:
            return None
        for name in dirnames:
            full = os.path.join(dirpath, name)
            try:
                child = os.lstat(full)
            except OSError:
                return None
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
                return None
            rows.append(_dir_row(root, full, child))
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                child = os.lstat(full)
            except OSError:
                return None
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISREG(child.st_mode):
                return None
            rows.append(_file_row(root, full, child))
    if failed:
        return None
    rows.sort()
    return _digest(rows)


def files_identity(paths: list[str]) -> str | None:
    """Name every path together. Takes the paths, in order. Returns the name, or None when any
    one of them cannot be named."""
    if not paths:
        return None
    parts: list[str] = []
    for path in paths:
        part = tree_identity(path)
        if part is None:
            return None
        parts.append(part)
    if len(parts) == 1:
        return parts[0]
    return _digest(parts)
