#!/usr/bin/env python3
"""What saw's hook has judged in a working tree, so a file checkout scans the files it wrote."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.bots.security import hookscript
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.lib.git.run import stdout_bytes
from stayawake.utils import atomicwrite

_VERSION = 1
_JUST_CHANGED_NS = 2_000_000_000
_LARGEST_RECORD = 256 * 1024 * 1024


@dataclass(frozen=True)
class Look:
    """The files of a working tree at one moment: each one's status by path, the ones a walk of the
    tree reaches, when the look began, and the largest file a scan reads in full."""

    files: dict[str, tuple]
    walked: frozenset[str]
    taken_ns: int
    largest: int


@dataclass
class Plan:
    """What a file checkout leaves to scan, and what the record keeps for the rest."""

    to_scan: tuple[str, ...]
    contents: dict[str, str | None] = field(default_factory=dict)
    kept: dict[str, list] = field(default_factory=dict)


def record_path(root: Path) -> Path:
    """Name the file that holds a working tree's record. Takes the working tree's root. Returns
    the path."""
    key = hashlib.sha256(os.fsencode(os.path.realpath(root))).hexdigest()[:32]
    return hookscript.checkout_records_dir() / f"{key}.json"


def look(root: Path, opts: ScanOptions) -> Look | None:
    """List the files a scan of a working tree reads, with every file the repository tracks inside a
    folder that walk skips, and their status. Takes the root and the scan options. Returns the look,
    or None when the tree or git's list of tracked files could not be read in full."""
    taken = time.time_ns()
    target = LocalRepoTarget(str(root), "", opts)
    walked = frozenset(target.iter_files())
    if target.read_errors:
        return None
    names = set(walked)
    tracked = stdout_bytes(root, ["ls-files", "-z"])
    if tracked is None:
        return None
    for raw in tracked.split(b"\0"):
        rel = os.fsdecode(raw)
        if raw and any(part in opts.exclude_dirs for part in Path(rel).parts[:-1]):
            names.add(rel)
    files = {}
    for rel in names:
        try:
            info = os.lstat(root / rel)
        except OSError:
            continue
        files[rel] = (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino, info.st_mode)
    return Look(files, walked & frozenset(files), taken, opts.max_file_bytes)


def content(root: Path, rel: str, status: tuple, largest: int) -> str | None:
    """Name a file's content. Takes the root, the path, the file's status and the largest file to
    read. Returns the target of a link or the digest of a regular file, or None for anything else,
    a larger file, or a file that cannot be read."""
    path = root / rel
    try:
        if stat.S_ISLNK(status[4]):
            return "link:" + os.readlink(path)
    except OSError:
        return None
    if not stat.S_ISREG(status[4]) or status[0] > largest:
        return None
    return hookscript.digest_file(path, largest)


def load(root: Path, policy: str) -> dict[str, list] | None:
    """Read a working tree's record. Takes the root and the digest of the policy in force. Returns
    the entries by path as `[status, content or None, judged clean, status settled]`, with every
    judgement made under another policy cleared, or None when there is no record that can be read."""
    held = atomicwrite.read_back(record_path(root), _LARGEST_RECORD)
    if held is None:
        return None
    try:
        data = json.loads(held)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or data.get("version") != _VERSION:
        return None
    files = data.get("files")
    if not isinstance(files, dict):
        return None
    same_policy = data.get("policy") == policy
    entries = {}
    for rel, entry in files.items():
        if not (isinstance(entry, list) and len(entry) == 4):
            return None
        status, held_content, clean, settled = entry
        if not (isinstance(status, list) and len(status) == 5 and all(type(n) is int for n in status)):
            return None
        if held_content is not None and not isinstance(held_content, str):
            return None
        entries[rel] = [tuple(status), held_content, clean is True and same_policy, settled is True]
    return entries


def plan(root: Path, now: Look, held: dict[str, list] | None) -> Plan:
    """Work out which files a file checkout leaves to scan. Takes the root, a look taken after the
    checkout and the record. Returns every file of the look when there is no record; otherwise each
    file that may have been written since the record and whose content is not one judged clean at
    that path."""
    if held is None:
        return Plan(tuple(sorted(now.files)))
    to_scan, contents, kept = [], {}, {}
    for rel, status in now.files.items():
        before = held.get(rel)
        if before is not None and before[0] == status and before[3]:
            kept[rel] = before
            continue
        named = content(root, rel, status, now.largest)
        unchanged = before is not None and named is not None and named == before[1]
        if unchanged and (before[0] == status or before[2]):
            kept[rel] = before
            continue
        to_scan.append(rel)
        contents[rel] = named
    return Plan(tuple(sorted(to_scan)), contents, kept)


def whole_read(now: Look) -> Plan:
    """Describe a scan that walked the whole tree. Takes the look taken before it. Returns a plan
    naming every file that walk reaches."""
    return Plan(tuple(sorted(now.walked)))


def remember(root: Path, now: Look, done: Plan, flagged: set[str], policy: str) -> bool:
    """Record what a completed scan judged. Takes the root, the look taken before the scan, the plan
    it scanned, the paths of its findings and the policy digest. Returns True when the record was
    written."""
    files = {}
    for rel, status in now.files.items():
        settled = max(status[1], status[2]) < now.taken_ns - _JUST_CHANGED_NS
        if rel in done.kept:
            before = done.kept[rel]
            files[rel] = [list(status), before[1], before[2], settled]
        elif rel in done.to_scan:
            named = done.contents[rel] if rel in done.contents else content(root, rel, status, now.largest)
            files[rel] = [list(status), named, named is not None and rel not in flagged, settled]
    text = json.dumps({"version": _VERSION, "policy": policy, "files": files})
    try:
        atomicwrite.make_folder(record_path(root).parent)
    except OSError:
        return False
    return atomicwrite.replace(record_path(root), text)
