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


def written(root: Path, opts: ScanOptions, since_ns: int) -> tuple[str, ...] | None:
    """List the files written into a working tree since a moment, among those a scan of the tree
    reads and those the repository tracks inside a folder that scan skips, with every link that leads
    to one of them. Takes the root, the scan options and the moment. Returns the paths, or None when
    the tree or git's list of tracked files could not be read in full."""
    target = LocalRepoTarget(str(root), "", opts)
    names = set(target.iter_files())
    if target.read_errors:
        return None
    tracked = stdout_bytes(root, ["ls-files", "-z"])
    if tracked is None:
        return None
    for raw in tracked.split(b"\0"):
        rel = os.fsdecode(raw)
        if raw and any(part in opts.exclude_dirs for part in Path(rel).parts[:-1]):
            names.add(rel)
    fresh, links = set(), []
    for rel in names:
        try:
            info = os.lstat(root / rel)
        except OSError:
            continue
        if info.st_ctime_ns >= since_ns - _CLOCK_SLACK_NS:
            fresh.add(rel)
        elif stat.S_ISLNK(info.st_mode):
            links.append(rel)
    if fresh and links:
        targets = {os.path.realpath(root / rel) for rel in fresh}
        fresh.update(rel for rel in links if os.path.realpath(root / rel) in targets)
    return tuple(sorted(fresh))
