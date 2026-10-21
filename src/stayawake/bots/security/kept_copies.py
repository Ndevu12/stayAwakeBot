#!/usr/bin/env python3
"""The copies an older `saw fix` kept in a repository, told apart by what the repository's own
history proves, and their removal once their fix is committed."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from stayawake.bots.security.models import ROLLBACK_DIR, SAW_DIR
from stayawake.lib.git.objects import blob_id
from stayawake.lib.git.query import path_key
from stayawake.lib.git.run import stdout_bytes
from stayawake.utils.pathsafe import entry_id, passes_through_a_link, read_regular_no_follow

_PATHS_PER_CALL = 256
_LARGEST_COPY = 64 * 1024 * 1024
_ROLLBACK_NAME = PurePosixPath(ROLLBACK_DIR).name


@dataclass(frozen=True)
class KeptCopy:
    """One copy an older `saw fix` kept: where it is, the file it is a copy of, and whether the
    fix of that file is committed."""

    path: str
    original: str
    fix_committed: bool


def proven(root: Path) -> list[KeptCopy] | None:
    """Find the copies an older `saw fix` kept that the repository's history proves. Takes the
    repository. Returns them, empty when there are none, or None when git could not say."""
    held = _held(Path(root))
    if not held:
        return []
    top = stdout_bytes(root, ["rev-parse", "--show-toplevel"])
    if top is None:
        return None
    if os.path.realpath(os.fsdecode(top.rstrip(b"\n"))) != os.path.realpath(root):
        return []
    in_index = _listed(root, ["ls-files", "-z"])
    in_head = _listed(root, ["ls-tree", "-r", "-z", "--name-only", "--full-tree", "HEAD"])
    oid_of = _object_id_function(root)
    if in_index is None or in_head is None or oid_of is None:
        return None
    key = path_key(root)
    names = in_index | in_head
    tracked = {key(path) for path in names}
    entries = _tracked_entries(Path(root), names)
    held = {path: data for path, data in held.items()
            if not _under_any(path, tracked, key)
            and not _shares_a_tracked_file(Path(root), path, entries)}
    copies = {path: (path[len(ROLLBACK_DIR) + 1:], oid_of(data)) for path, data in held.items()}
    committed = _committed_versions(root, sorted({original for original, _ in copies.values()}))
    if committed is None:
        return None
    copies = {path: version for path, version in copies.items() if version in committed}
    if not copies:
        return []
    at_head = _versions_at_head(root, sorted({original for original, _ in copies.values()}))
    if at_head is None:
        return None
    return [KeptCopy(path, original, at_head.get(original) != oid
                     and _on_disk(Path(root) / original) != held[path])
            for path, (original, oid) in sorted(copies.items())]


def remove_fixed(root: Path) -> tuple[list[str], list[str]]:
    """Remove the proven copies whose fix is committed, and the folders they leave empty. Takes the
    repository. Returns the copies removed and those that could not be."""
    copies = proven(root) or []
    removed: list[str] = []
    left: list[str] = []
    for copy in (c for c in copies if c.fix_committed):
        where = Path(root) / copy.path
        try:
            if passes_through_a_link(Path(root), where):
                raise OSError("a folder on the way is a link")
            os.unlink(where)
            removed.append(copy.path)
        except OSError:
            left.append(copy.path)
    _drop_empty_folders(Path(root))
    return removed, left


def _held(root: Path) -> dict[str, bytes]:
    """Read every file and link under the rollback folder, outside any repository within it. Takes
    the repository. Returns each one's bytes by its path, empty when the folder is not there under
    exactly its own name or is reached through a link."""
    folder = root / ROLLBACK_DIR
    if (not _named_exactly(root, SAW_DIR) or not _named_exactly(root / SAW_DIR, _ROLLBACK_NAME)
            or passes_through_a_link(root, folder) or folder.is_symlink() or not folder.is_dir()
            or os.path.lexists(root / SAW_DIR / ".git") or os.path.lexists(folder / ".git")):
        return {}
    held: dict[str, bytes] = {}
    for top, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if not os.path.lexists(os.path.join(top, d, ".git"))]
        for name in [*files, *(d for d in dirs if os.path.islink(os.path.join(top, d)))]:
            data = _on_disk(Path(top) / name)
            if data is not None:
                held[(Path(top) / name).relative_to(root).as_posix()] = data
    return held


def _on_disk(path: Path) -> bytes | None:
    """Read what git would store for a path. Takes the path. Returns a link's target or a file's
    bytes, or None when it is neither or cannot be read."""
    try:
        if path.is_symlink():
            return os.fsencode(os.readlink(path))
        return read_regular_no_follow(path, _LARGEST_COPY)
    except OSError:
        return None


def _object_id_function(root: Path):
    """Pick how the repository names stored content. Takes the repository. Returns a function from
    bytes to their object id, or None when git could not say."""
    answer = stdout_bytes(root, ["rev-parse", "--show-object-format"])
    if answer is None:
        return None
    return lambda data: blob_id(data, os.fsdecode(answer.strip()))


def _committed_versions(root: Path, originals: list[str]) -> set[tuple[str, str]] | None:
    """List every version any commit stored at the given paths. Takes the repository and the paths.
    Returns `(path, object id)` pairs, or None when git could not say."""
    versions: set[tuple[str, str]] = set()
    for start in range(0, len(originals), _PATHS_PER_CALL):
        chunk = originals[start:start + _PATHS_PER_CALL]
        listed = stdout_bytes(root, ["log", "HEAD", "--root", "-m", "--no-renames", "--format=",
                                     "--raw", "-z", "--no-abbrev", "--", *chunk])
        if listed is None:
            return None
        fields = iter(listed.split(b"\0"))
        for meta in fields:
            parts = meta.lstrip(b"\n").split()
            if len(parts) != 5 or not parts[0].startswith(b":"):
                continue
            path = os.fsdecode(next(fields, b""))
            versions.update((path, oid.decode("ascii")) for oid in parts[2:4] if oid.strip(b"0"))
    return versions


def _versions_at_head(root: Path, originals: list[str]) -> dict[str, str] | None:
    """Read what the current commit stores at the given paths. Takes the repository and the paths.
    Returns each stored path's object id, or None when git could not say."""
    at_head: dict[str, str] = {}
    for start in range(0, len(originals), _PATHS_PER_CALL):
        chunk = originals[start:start + _PATHS_PER_CALL]
        listed = stdout_bytes(root, ["ls-tree", "-r", "-z", "--full-tree", "HEAD", "--", *chunk])
        if listed is None:
            return None
        for entry in filter(None, listed.split(b"\0")):
            meta, _, path = entry.partition(b"\t")
            parts = meta.split()
            if len(parts) == 3:
                at_head[os.fsdecode(path)] = parts[2].decode("ascii")
    return at_head


def _listed(root: Path, args: list[str]) -> set[str] | None:
    """Run a git listing. Takes the repository and the arguments. Returns the paths it names, or
    None when git could not say."""
    listed = stdout_bytes(root, args)
    return None if listed is None else {os.fsdecode(p) for p in listed.split(b"\0") if p}


def _named_exactly(folder: Path, name: str) -> bool:
    """Tell whether a folder holds an entry by exactly this name. Takes the folder and the name.
    Returns the answer, False when the folder cannot be listed."""
    try:
        return name in os.listdir(folder)
    except OSError:
        return False


def _tracked_entries(root: Path, paths: set[str]) -> set[tuple[int, int]]:
    """Name the directory entries git tracks. Takes the repository and the tracked paths. Returns
    the entries that could be read."""
    found = set()
    for path in paths:
        ident = entry_id(root / path)
        if ident is not None:
            found.add(ident)
    return found


def _shares_a_tracked_file(root: Path, path: str, tracked: set[tuple[int, int]]) -> bool:
    """Tell whether a path is a tracked file. Takes the repository, the path and the tracked
    entries. Returns the answer, True when the path cannot be identified."""
    ident = entry_id(root / path)
    if ident is None:
        return True
    return ident in tracked


def _under_any(path: str, tracked: set[str], key) -> bool:
    """Tell whether git tracks a path or a folder above it. Takes the path, the tracked paths under
    `key`, and that key. Returns the answer."""
    here = PurePosixPath(key(path))
    return any(str(p) in tracked for p in (here, *here.parents))


def _drop_empty_folders(root: Path) -> None:
    """Remove the rollback folder's empty folders, then it and saw's own folder when empty. Takes
    the repository. Returns nothing."""
    folder = root / ROLLBACK_DIR
    if passes_through_a_link(root, folder) or folder.is_symlink() or not folder.is_dir():
        return
    for top, _, _ in sorted(os.walk(folder), key=lambda entry: -len(entry[0])):
        try:
            os.rmdir(top)
        except OSError:
            continue
    try:
        os.rmdir(root / SAW_DIR)
    except OSError:
        pass
