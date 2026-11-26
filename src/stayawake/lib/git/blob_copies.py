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
from stayawake.lib.git.write.working_tree import TreeStateUnknown, bytes_as_written, landing_entries
from stayawake.utils import atomicwrite, pathsafe, scratch

_BLOBS_PER_READ = 256
_LARGEST_BATCHED_BLOB = 16 << 20
_MOST_BYTES_PER_READ = 128 << 20

_FREE = "free"
_PLACED = "placed"
_NAME_IN_USE = "name in use"
_CANNOT_HOLD_A_FILE = "cannot hold a file"

ON_WINDOWS = os.name == "nt"
_CHARACTERS_WINDOWS_REFUSES = frozenset('<>:"|?*\\') | frozenset(chr(code) for code in range(32))
_NAMES_WINDOWS_RESERVES = frozenset({"con", "prn", "aux", "nul", "conin$", "conout$",
                                     *(f"{port}{number}" for port in ("com", "lpt")
                                       for number in (*"123456789", "\u00b9", "\u00b2", "\u00b3"))})


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


def copy_out_blobs(repo: Path, named: tuple[tuple[str, str], ...], purpose: str) -> BlobCopies:
    """Copy each named blob under its path, into folders laid out as `_in_folders` lays them. Takes
    the repository, each path with its blob id, and what the copies are for. Returns the copies,
    with each blob the repository does not hold listed as not copied."""
    contents = _read(repo, [oid for _path, oid in named])
    return _in_folders([(path, contents.get(oid)) for path, oid in named], purpose)


def copy_out_files(top: Path, paths: tuple[str, ...], purpose: str) -> BlobCopies:
    """Copy each path's bytes the folder holds now, into folders laid out as `_in_folders` lays
    them. Takes the top of the working tree, the paths and what the copies are for. Returns the
    copies, leaving out each path that is not a regular file inside the folder."""
    root = os.path.realpath(top)
    files: list[tuple[str, bytes | None]] = []
    for rel in paths:
        where = Path(top) / rel
        if not os.path.realpath(where).startswith(root.rstrip(os.sep) + os.sep):
            continue
        data = pathsafe.read_regular_no_follow(where, _LARGEST_BATCHED_BLOB)
        if data is not None:
            files.append((rel, data))
    return _in_folders(files, purpose)


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
    digests = tuple((os.fsdecode(name), hashlib.sha256(written[name]).hexdigest())
                    for name in recorded if name in written)
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
    if ON_WINDOWS and not _windows_can_hold(rel):
        return _CANNOT_HOLD_A_FILE
    destination = folder / rel
    free = _free(destination)
    if free != _FREE:
        return free
    try:
        _make_folder(destination.parent)
    except (NotADirectoryError, FileExistsError):
        return _NAME_IN_USE
    except OSError:
        return _CANNOT_HOLD_A_FILE
    if _free(destination) != _FREE:
        return _NAME_IN_USE
    if not _write(destination, data):
        _remove(destination)
        return _CANNOT_HOLD_A_FILE
    try:
        written = os.lstat(destination)
    except OSError:
        _remove(destination)
        return _CANNOT_HOLD_A_FILE
    return _PLACED if written.st_size == len(data) else _CANNOT_HOLD_A_FILE


def _windows_can_hold(rel: str) -> bool:
    """Tell whether Windows can hold a file under this name, each part of it a name it neither
    refuses nor reserves for a device. Takes the name, its parts split by `/`. Returns the answer."""
    for part in rel.split("/"):
        if (not part or part in (".", "..") or part[-1] in ". " or set(part) & _CHARACTERS_WINDOWS_REFUSES
                or part.split(".")[0].rstrip(" ").lower() in _NAMES_WINDOWS_RESERVES):
            return False
    return True


def _make_folder(folder: Path) -> None:
    """Make a folder and every missing folder above it, without following a link on POSIX. Takes
    the folder. Raises `OSError` when it cannot be made."""
    if ON_WINDOWS:
        os.makedirs(folder, exist_ok=True)
    else:
        atomicwrite.make_folder(folder)


def _write(destination: Path, data: bytes) -> bool:
    """Write a new file's bytes and read them back, untranslated. Takes the path and the bytes.
    Returns whether the file now holds exactly them."""
    if not ON_WINDOWS:
        return atomicwrite.replace(destination, data)
    try:
        with open(destination, "xb") as handle:
            handle.write(data)
        with open(destination, "rb") as handle:
            return handle.read(len(data) + 1) == data
    except OSError:
        return False


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
    """List every file and link `commit` records with its blob, under the name a move writes it.
    Takes the repository and the commit. Returns each name's blob id, or None when git could not
    list them."""
    try:
        listed = landing_entries(repo, commit)
    except (TreeStateUnknown, ValueError):
        return None
    return {path: oid.decode() for path, (mode, oid) in listed.items() if mode in FILE_AND_LINK_MODES}


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
