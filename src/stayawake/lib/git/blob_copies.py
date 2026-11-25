#!/usr/bin/env python3
"""Copy the files a commit records out of a repository by their blobs, each under its own name, into
folders where no two names share a file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import objects
from stayawake.lib.git.run import UNTRUSTED, stdout_bytes
from stayawake.utils import atomicwrite, scratch

_FILE_MODES = (b"100644", b"100755", b"120000")
_BLOBS_PER_READ = 256
_LARGEST_BATCHED_BLOB = 16 << 20
_MOST_BYTES_PER_READ = 128 << 20

_FREE = "free"
_PLACED = "placed"
_NAME_IN_USE = "name in use"
_CANNOT_HOLD_A_FILE = "cannot hold a file"


@dataclass(frozen=True)
class BlobCopies:
    """The copied files: each folder with the names it holds, and the names whose bytes could not
    be copied."""

    folders: tuple[tuple[Path, tuple[str, ...]], ...]
    not_copied: tuple[str, ...]


def copy_out(repo: Path, commit: str, paths: tuple[str, ...], purpose: str) -> BlobCopies:
    """Copy each path's blob at `commit` under its own name, putting a name that would share a file
    with one already copied in a further folder. Takes the repository, the commit, the paths and
    what the copies are for. Returns the folders and the names that could not be copied, leaving
    out each path the commit records no file for."""
    recorded = _file_entries(repo, commit)
    if recorded is None:
        return BlobCopies((), tuple(paths))
    wanted = [rel for rel in paths if os.fsencode(rel) in recorded]
    contents = _read(repo, [recorded[os.fsencode(rel)] for rel in wanted])
    folders: list[tuple[Path, list[str]]] = []
    not_copied: list[str] = []
    for rel in wanted:
        data = contents.get(recorded[os.fsencode(rel)])
        if data is None or not _copied(folders, rel, data, purpose):
            not_copied.append(rel)
    return BlobCopies(tuple((folder, tuple(names)) for folder, names in folders), tuple(not_copied))


def _copied(folders: list[tuple[Path, list[str]]], rel: str, data: bytes, purpose: str) -> bool:
    """Write one file into the first folder where its name is free, or into a new one. Takes the
    folders made, the name, its bytes and what the copies are for. Returns whether it was
    written."""
    for folder, names in folders:
        outcome = _place(folder, rel, data)
        if outcome == _NAME_IN_USE:
            continue
        if outcome == _PLACED:
            names.append(rel)
        return outcome == _PLACED
    folder = scratch.new_dir(purpose)
    if _place(folder, rel, data) != _PLACED:
        scratch.release_path(folder)
        return False
    folders.append((folder, [rel]))
    return True


def _place(folder: Path, rel: str, data: bytes) -> str:
    """Write `data` at `rel` in `folder` where no file there answers to that name. Takes the
    folder, the name and the bytes. Returns placed, name in use, or cannot hold a file."""
    destination = folder / rel
    free = _free(destination)
    if free != _FREE:
        return free
    try:
        atomicwrite.make_folder(destination.parent)
    except NotADirectoryError:
        return _NAME_IN_USE
    except OSError:
        return _CANNOT_HOLD_A_FILE
    if _free(destination) != _FREE:
        return _NAME_IN_USE
    if not atomicwrite.replace(destination, data):
        _remove(destination)
        return _CANNOT_HOLD_A_FILE
    try:
        written = os.lstat(destination)
    except OSError:
        _remove(destination)
        return _CANNOT_HOLD_A_FILE
    return _PLACED if written.st_size == len(data) else _CANNOT_HOLD_A_FILE


def _free(destination: Path) -> str:
    """Look up `destination` before a file is written there. Takes the path. Returns free, name in
    use, or cannot hold a file."""
    try:
        os.lstat(destination)
    except FileNotFoundError:
        return _FREE
    except NotADirectoryError:
        return _NAME_IN_USE
    except OSError:
        return _CANNOT_HOLD_A_FILE
    return _NAME_IN_USE


def _remove(destination: Path) -> None:
    """Remove a file a failed copy left. Takes its path."""
    try:
        os.unlink(destination)
    except OSError:
        pass


def _file_entries(repo: Path, commit: str) -> dict[bytes, str] | None:
    """List every file `commit` records with its blob. Takes the repository and the commit. Returns
    each path's blob id, or None when git could not list them."""
    listed = stdout_bytes(repo, ["ls-tree", "-r", "-z", "--full-tree", commit], context=UNTRUSTED)
    if listed is None:
        return None
    entries: dict[bytes, str] = {}
    for record in listed.split(b"\0"):
        described, _, path = record.partition(b"\t")
        parts = described.split(b" ")
        if len(parts) == 3 and parts[0] in _FILE_MODES and parts[1] == b"blob":
            entries[path] = parts[2].decode()
    return entries


def _read(repo: Path, oids: list[str]) -> dict[str, bytes]:
    """Read blobs, many to a git call, and one at a time any a batch left out. Takes the
    repository and the blob ids. Returns each blob read, by its id."""
    contents: dict[str, bytes] = {}
    unique = list(dict.fromkeys(oids))
    for start in range(0, len(unique), _BLOBS_PER_READ):
        batch = unique[start:start + _BLOBS_PER_READ]
        read, _sizes = objects.read_blobs(repo, batch, max_each=_LARGEST_BATCHED_BLOB,
                                          max_total=_MOST_BYTES_PER_READ)
        contents.update(read)
        for oid in batch:
            if oid not in contents:
                data = objects.blob(repo, oid)
                if data is not None:
                    contents[oid] = data
    return contents
