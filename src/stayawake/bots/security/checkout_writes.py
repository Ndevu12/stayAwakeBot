#!/usr/bin/env python3
"""The files the git command that ran saw's hook wrote into a working tree."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.lib.git.run import stdout_bytes
from stayawake.utils import procsnap

_CLOCK_SLACK_NS = 2_000_000_000
_ANCESTORS_LOOKED_AT = 8


def git_started_ns() -> int | None:
    """Find when the git command that ran this process started. Returns the start of the nearest
    process above this one that runs git, as wall-clock nanoseconds, or None when there is none or
    it cannot be read."""
    pid = os.getppid()
    for _ in range(_ANCESTORS_LOOKED_AT):
        start = procsnap.started(pid)
        if start is None:
            return None
        if start.name == "git" or start.name.startswith("git-"):
            return start.at_ns
        if start.ppid <= 1:
            return None
        pid = start.ppid
    return None


def _identity(path: Path) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
    except (OSError, ValueError):
        return None
    return info.st_dev, info.st_ino


def written(root: Path, opts: ScanOptions, since_ns: int) -> tuple[str, ...] | None:
    """List the files and links written into a working tree since a moment, among those a scan of
    the tree reads and those the repository tracks, with every link that leads to a written file, or
    every link when one was written. Takes the root, the scan options and the moment. Returns the
    paths, or None when the tree or git's list of tracked files could not be read in full."""
    target = LocalRepoTarget(str(root), "", opts)
    names = set(target.iter_files())
    if target.read_errors:
        return None
    tracked = stdout_bytes(root, ["ls-files", "-z"])
    if tracked is None:
        return None
    names.update(os.fsdecode(raw) for raw in tracked.split(b"\0") if raw)
    fresh, links, link_written = set(), [], False
    for rel in names:
        try:
            info = os.lstat(root / rel)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode):
            continue
        is_link = stat.S_ISLNK(info.st_mode)
        if info.st_ctime_ns >= since_ns - _CLOCK_SLACK_NS:
            fresh.add(rel)
            link_written = link_written or is_link
        elif is_link:
            links.append(rel)
    if fresh and links:
        if link_written:
            fresh.update(links)
        else:
            targets = {_identity(root / rel) for rel in fresh} - {None}
            fresh.update(rel for rel in links if _identity(root / rel) in targets)
    return tuple(sorted(fresh))
