#!/usr/bin/env python3
"""Every version a repository still stores, presented through the interface a directory uses, so
every matcher applies to it without knowing where it came from."""
from __future__ import annotations

import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from stayawake.lib.git.query import reachable_blobs

from .base import TRUNCATION_MARKER, Target

_CHUNK = 1 << 20


def versions_by_path(root, limit: int = 200_000) -> tuple[dict[str, list[str]], bool]:
    """Stored blob shas grouped by the path they are known by, and whether the walk completed."""
    blobs, complete = reachable_blobs(root, limit=limit)
    grouped: dict[str, list[str]] = defaultdict(list)
    for sha, path in blobs:
        grouped[path].append(sha)
    return dict(grouped), complete


class HistoryTarget(Target):
    """One stored version of each path — round `index`, counting from 0.

    `rel` is the REAL path, never a path with an identity encoded into it. A sha in the name defeats
    everything that matches on a path: `tests/**` stops matching its allowlist rule, and a name that
    no longer ends in `.js` stops matching an extension. MEASURED, both — together they gave 656 of
    this repository's own fixtures and reports a "confirmed payload" verdict.

    The version is chosen by the round instead. Rounds map to PATH coverage: one covers 74% of this
    repository's paths completely, twenty covers 98.6%, and the remainder is files CI rewrites on
    every run.

    `exclude_dirs` is deliberately NOT applied. `rev-list --objects` emits a blob once, under one of
    its names, so excluding by that name drops content that also lives at a scanned path — and
    whoever committed it chooses which name git emits. Reading a vendored tree is noise; not reading
    a payload because it is also filed under `node_modules/` is a blind spot someone can aim.
    """

    source = "history"

    def __init__(self, root, display: str, opts, versions: dict[str, list[str]], index: int = 0):
        super().__init__(root, display, opts)
        self._sha_by_path = {path: shas[index] for path, shas in versions.items()
                             if index < len(shas)}

    def __len__(self) -> int:
        return len(self._sha_by_path)

    def iter_files(self) -> Iterator[str]:
        yield from self._sha_by_path

    def sha_for(self, rel: str) -> str | None:
        return self._sha_by_path.get(rel)

    def read_bytes(self, rel: str, limit: int | None = None) -> bytes | None:
        data, more = self._stream(rel, limit if limit else self.opts.max_file_bytes)
        if data is None or limit:
            return data
        return None if more else data          # oversized: a policy skip, exactly as the tree side

    # Three readers reach the filesystem on the base class, and the content tier — the one carrying
    # every confirmed signature — uses `read_source_windows`, not `read_bytes`. Overriding one of
    # the three scanned nothing and reported clean.
    def read_text(self, rel: str) -> str | None:
        data = self.read_bytes(rel)
        if data is None:
            data = self._head_tail(rel)        # oversized, so the tree side's head+tail, not a skip
        if data is None:
            return None
        return data.replace(b"\x00", b"").decode("utf-8", "replace")   # as the tree side decodes

    def read_source_windows(self, rel: str) -> Iterator[tuple[int, str]]:
        text = self.read_text(rel)
        if text:
            yield 0, text

    def _cat_file(self, sha: str):
        return subprocess.Popen(["git", "-C", str(Path(self.root)), "cat-file", "blob", sha],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def _stream(self, rel: str, cap: int) -> tuple[bytes | None, bool]:
        """At most `cap` bytes of a stored version, and whether there were more.

        Streamed and capped rather than captured whole: a size test after the read cannot bound it,
        because the read itself is what costs. The tree side stats before opening; a stored version
        has nothing to stat, so the cap moves into the read.
        """
        sha = self._sha_by_path.get(rel)
        if sha is None:
            return None, False
        try:
            proc = self._cat_file(sha)
            with proc:
                data = proc.stdout.read(cap) or b""
                more = bool(proc.stdout.read(1))
                if more:
                    proc.kill()
            if proc.returncode not in (0, -9):
                self.read_errors.append(rel)
                return None, False
        except (OSError, subprocess.SubprocessError):
            self.read_errors.append(rel)
            return None, False
        return data, more

    def _head_tail(self, rel: str) -> bytes | None:
        """The two ends of an oversized version, as the tree side reads an oversized file.

        Consumed in chunks and thrown away in the middle, so memory stays at the two ends however
        large the blob is. Drained to the end rather than stopped at a ceiling: a payload is usually
        APPENDED, and stopping early makes the "tail" a middle slice that silently misses it.
        """
        half = max(1, self.opts.max_file_bytes // 2)
        sha = self._sha_by_path.get(rel)
        if sha is None:
            return None
        head, tail, total = b"", b"", 0
        try:
            proc = self._cat_file(sha)
            with proc:
                while True:
                    chunk = proc.stdout.read(_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if len(head) < half:
                        head += chunk[:half - len(head)]
                    tail = (tail + chunk)[-half:]
        except (OSError, subprocess.SubprocessError):
            self.read_errors.append(rel)
            return None
        return head if total <= half else head + TRUNCATION_MARKER + tail
