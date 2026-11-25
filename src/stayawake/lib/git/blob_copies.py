#!/usr/bin/env python3
"""Copy the files a commit records out of a repository by their blobs, each under its own name, into
folders where no two names share a file."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import objects
from stayawake.lib.git.borrowed import object_directory
from stayawake.lib.git.objects import FILE_AND_LINK_MODES
from stayawake.lib.git.run import UNTRUSTED, stdout_bytes
from stayawake.lib.git.write.working_tree import bytes_as_written
from stayawake.utils import atomicwrite, scratch

_BLOBS_PER_READ = 256
_LARGEST_BATCHED_BLOB = 16 << 20
_MOST_BYTES_PER_READ = 128 << 20

_FREE = "free"
_PLACED = "placed"
_NAME_IN_USE = "name in use"
_CANNOT_HOLD_A_FILE = "cannot hold a file"


@dataclass(frozen=True)
class BlobCopies:
    """The copied files: each folder with the names it holds, the names whose bytes could not be
    copied, and each name's sha256 of the bytes that land in the folder, when copied as written."""

    folders: tuple[tuple[Path, tuple[str, ...]], ...]
    not_copied: tuple[str, ...]
    digests: tuple[tuple[str, str], ...] = ()


def copy_out(repo: Path, commit: str, paths: tuple[str, ...], purpose: str) -> BlobCopies:
    """Copy each path's blob at `commit` under its own name, into folders laid out as `_in_folders`
    lays them. Takes the repository, the commit, the paths and what the copies are for. Returns the
    copies, leaving out each path the commit records no file for."""
    recorded = _file_entries(repo, commit)
    if recorded is None:
        return BlobCopies((), tuple(paths))
    wanted = [rel for rel in paths if os.fsencode(rel) in recorded]
    contents = _read(repo, [recorded[os.fsencode(rel)] for rel in wanted])
    return _in_folders([(rel, contents.get(recorded[os.fsencode(rel)])) for rel in wanted], purpose)


def copy_out_as_written(repo: Path, holding: Path, commit: str, paths: tuple[str, ...],
                        purpose: str) -> BlobCopies:
    """Copy each path in the form a move to `commit` writes into `repo`'s working tree, and its
    stored blob too where the two differ, into folders laid out by `_in_folders`. Takes the
    operator's repository, a repository holding the commit, the commit, the paths and what the
    copies are for. Returns the copies with the digest of each written file, leaving out each path
    the commit records no file for."""
    recorded = _file_entries(holding, commit)
    store = object_directory(holding)
    if recorded is None or store is None:
        return BlobCopies((), tuple(paths))
    wanted = [rel for rel in paths if os.fsencode(rel) in recorded]
    written = bytes_as_written(repo, commit, [os.fsencode(rel) for rel in wanted], store) or {}
    stored = _read(holding, [recorded[os.fsencode(rel)] for rel in wanted])
    files: list[tuple[str, bytes | None]] = []
    for rel in wanted:
        landing = written.get(os.fsencode(rel))
        files.append((rel, landing))
        blob = stored.get(recorded[os.fsencode(rel)])
        if landing is not None and blob is not None and blob != landing:
            files.append((rel, blob))
    digests = tuple((rel, hashlib.sha256(written[os.fsencode(rel)]).hexdigest())
                    for rel in wanted if os.fsencode(rel) in written)
    return _in_folders(files, purpose, digests)


def _in_folders(files: list[tuple[str, bytes | None]], purpose: str,
                digests: tuple[tuple[str, str], ...] = ()) -> BlobCopies:
    """Write each file under its own name. The first folder holds every name that shares a file with
    no name before it. Each further folder holds names that would share a file in the folders before
    it, with every file of the first folder whose name is still free there. Takes the files as
    (name, bytes or None), what the copies are for and the digests to carry. Returns the copies."""
    not_copied = [rel for rel, data in files if data is None]
    waiting = [(rel, data) for rel, data in files if data is not None]
    folders: list[tuple[Path, tuple[str, ...]]] = []
    shared: list[tuple[str, bytes]] = []
    while waiting:
        folder = scratch.new_dir(purpose)
        placed, waiting = _fill(folder, waiting, not_copied)
        if not placed:
            scratch.release_path(folder)
            continue
        if folders:
            placed += _fill(folder, shared, [])[0]
        else:
            shared = placed
        folders.append((folder, tuple(rel for rel, _ in placed)))
    return BlobCopies(tuple(folders), tuple(dict.fromkeys(not_copied)), digests)


def _fill(folder: Path, files: list[tuple[str, bytes]],
          not_copied: list[str]) -> tuple[list[tuple[str, bytes]], list[tuple[str, bytes]]]:
    """Write each file whose name is free in `folder`. Takes the folder, the files as (name, bytes)
    and the list a name that cannot hold a file is added to. Returns the files written and the
    files whose name was in use."""
    placed, in_use = [], []
    for rel, data in files:
        outcome = _place(folder, rel, data)
        if outcome == _PLACED:
            placed.append((rel, data))
        elif outcome == _NAME_IN_USE:
            in_use.append((rel, data))
        else:
            not_copied.append(rel)
    return placed, in_use


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
        if len(parts) == 3 and parts[0] in FILE_AND_LINK_MODES and parts[1] == b"blob":
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
