#!/usr/bin/env python3
"""Scan stored file versions in batches that hold each path once."""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from stayawake.lib.git import objects
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import PushedTarget

PATHS_PER_BATCH = 64
LFS_SPEC_URLS = (b"https://git-lfs.github.com/spec/v1", b"https://hawser.github.com/spec/v1",
                 b"http://git-media.io/v/2")
LFS_POINTER_MAX_BYTES = 1024


@dataclass
class BatchScan:
    """Hold what one batch's scan found.

    `findings` pairs each finding with the version it came from, or None; `unread` are the paths not
    read; `outside_git` are the paths whose version points to a file kept outside git, and
    `runnable` those of them that git stores as a program or that have no extension.
    """

    findings: list = field(default_factory=list)
    unread: set[str] = field(default_factory=set)
    runnable: set[str] = field(default_factory=set)
    outside_git: set[str] = field(default_factory=set)


def is_lfs_pointer(data: bytes) -> bool:
    """Tell whether stored bytes are a Git LFS pointer. Takes the bytes. Returns True when git-lfs
    reads them as one."""
    if not data or len(data) > LFS_POINTER_MAX_BYTES:
        return False
    first = data.strip().split(b"\n", 1)[0].strip()
    return any(first == b"version " + url for url in LFS_SPEC_URLS)


def batches(queue: list) -> list[list]:
    """Split versions into scan batches that hold each path once. Takes the versions, each with a
    `path`. Returns the batches, in order."""
    out: list[list] = []
    open_batches: list[int] = []
    last_batch: dict[str, int] = {}
    for entry in queue:
        at = bisect.bisect_right(open_batches, last_batch.get(entry.path, -1))
        if at < len(open_batches):
            index = open_batches[at]
            out[index].append(entry)
            if len(out[index]) >= PATHS_PER_BATCH:
                del open_batches[at]
        else:
            index = len(out)
            out.append([entry])
            if PATHS_PER_BATCH > 1:
                open_batches.append(index)
        last_batch[entry.path] = index
    return out


def scan_batch(repo: Path, display: str, batch: list, merges: list[str], signatures, allowlist,
               opts) -> BatchScan:
    """Scan one batch of stored versions. Takes the repository, how it is shown, the versions, each
    with `path`, `oid` and `link`, the merges to judge with them, and the signatures, allowlist and
    scan options. Returns the `BatchScan`."""
    files = {e.path: e.oid for e in batch if not e.link}
    links_wanted = {e.path: e.oid for e in batch if e.link}
    text_of, _all = objects.link_targets(repo, list(links_wanted.values()))
    links = {path: [text_of[oid]] for path, oid in links_wanted.items() if oid in text_of}
    target = PushedTarget(repo, display, opts, files, links, merges)
    result = scan_target(target, signatures, allowlist)
    by_path = {e.path: e for e in batch}
    unread = set(getattr(target, "read_errors", []))
    unread |= {path for path, oid in links_wanted.items() if oid not in text_of}
    if result.error:
        unread |= set(by_path) - {f.path for f in result.findings}
    outside_git = {e.path for e in batch if is_lfs_pointer(target.read_ahead.get(e.oid, b""))}
    runnable = {p for p in outside_git
                if getattr(by_path.get(p), "executable", False) or not PurePosixPath(p).suffix}
    return BatchScan(
        findings=[(f, by_path.get(f.path)) for f in result.findings],
        unread=unread,
        runnable=runnable,
        outside_git=outside_git)
