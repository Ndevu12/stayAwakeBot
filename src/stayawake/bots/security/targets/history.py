#!/usr/bin/env python3
"""Every version a repository still stores, presented through the interface a directory uses, so
every matcher applies to it without knowing where it came from."""
from __future__ import annotations

import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from stayawake.lib.git.query import reachable_blobs

from .base import Target


def versions_by_path(root, limit: int = 200_000) -> tuple[dict[str, list[str]], bool]:
    """Stored blob shas grouped by the path they are known by, and whether the walk completed."""
    blobs, complete = reachable_blobs(root, limit=limit)
    grouped: dict[str, list[str]] = defaultdict(list)
    for sha, path in blobs:
        grouped[path].append(sha)
    return dict(grouped), complete


def _excluded(path: str, exclude_dirs) -> bool:
    """Whether the tree scan would have skipped this path.

    The walk drops these directories, so reading their stored versions would answer differently
    about the same repository — and a project that once committed `node_modules` carries thousands
    of vendored files that the tree side deliberately never reads.
    """
    return any(part in exclude_dirs for part in Path(path).parts[:-1])


class HistoryTarget(Target):
    """One stored version of each path — round `index`, counting from 0.

    `rel` is the REAL path, never a path with an identity encoded into it. A sha in the name defeats
    everything that matches on a path: `tests/**` stops matching its allowlist rule, and a name that
    no longer ends in `.js` stops matching an extension. MEASURED, both — together they gave 656 of
    this repository's own fixtures and reports a "confirmed payload" verdict.

    The version is chosen by the round instead. Rounds map to PATH coverage: one covers 74% of this
    repository's paths completely, twenty covers 98.6%, and the remainder is files CI rewrites on
    every run.
    """

    source = "history"

    def __init__(self, root, display: str, opts, versions: dict[str, list[str]], index: int = 0):
        super().__init__(root, display, opts)
        self._sha_by_path = {path: shas[index] for path, shas in versions.items()
                             if index < len(shas) and not _excluded(path, opts.exclude_dirs)}

    def __len__(self) -> int:
        return len(self._sha_by_path)

    def iter_files(self) -> Iterator[str]:
        yield from self._sha_by_path

    def sha_for(self, rel: str) -> str | None:
        return self._sha_by_path.get(rel)

    def read_bytes(self, rel: str, limit: int | None = None) -> bytes | None:
        sha = self._sha_by_path.get(rel)
        if sha is None:
            return None
        try:
            out = subprocess.run(["git", "-C", str(Path(self.root)), "cat-file", "blob", sha],
                                 capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            self.read_errors.append(f"{rel} ({type(exc).__name__})")
            return None
        if out.returncode != 0:
            self.read_errors.append(f"{rel} (unreadable object)")
            return None
        data = out.stdout
        if limit is None and len(data) > self.opts.max_file_bytes:
            return None
        return data[:limit] if limit else data

    # Three readers reach the filesystem on the base class, and the content tier — the one carrying
    # every confirmed signature — uses `read_source_windows`, not `read_bytes`. Overriding one of
    # the three scanned nothing and reported clean.
    def read_text(self, rel: str) -> str | None:
        data = self.read_bytes(rel)
        return None if data is None else data.decode("utf-8", "replace")

    def read_source_windows(self, rel: str) -> Iterator[tuple[int, str]]:
        text = self.read_text(rel)
        if text:
            yield 0, text
