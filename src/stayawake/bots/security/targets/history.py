#!/usr/bin/env python3
"""Every version a repository still stores, presented through the interface a directory uses, so
every matcher applies to it without knowing where it came from."""
from __future__ import annotations

import os
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from stayawake.lib.git import lfs
from stayawake.lib.git.objects import own_view
from stayawake.lib.git.query import reachable_blobs
from stayawake.lib.git.run import open_stdout

from .base import SOURCE_EXTS, TRUNCATION_MARKER, Target, _ext, stream_windows

_CHUNK = 1 << 20


def versions_by_path(root, limit: int = 200_000,
                     offline: bool = True) -> tuple[dict[str, list[str]], bool]:
    """Stored blob shas grouped by the path they are known by, and whether the walk completed."""
    blobs, complete = reachable_blobs(root, limit=limit, offline=offline)
    grouped: dict[str, list[str]] = defaultdict(list)
    for sha, path in blobs:
        grouped[path].append(sha)
    return dict(grouped), complete


class _ObjectStream:
    """Read a local Git LFS object the way a stored blob is streamed."""

    returncode = 0

    def __init__(self, path: Path):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        self.stdout = os.fdopen(fd, "rb")

    def kill(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        self.stdout.close()
        return False


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
    reads_checkout = False

    def __init__(self, root, display: str, opts, versions: dict[str, list[str]],
                 index: int = 0, links: dict[str, list[str]] | None = None):
        super().__init__(root, display, opts)
        self._sha_by_path = {path: shas[index] for path, shas in versions.items()
                             if index < len(shas)}
        self.stored_links = links or {}
        self.read_ahead: dict[str, bytes] = {}
        self.sizes: dict[str, int] = {}
        self.read_in_part: set[str] = set()
        self.objects: dict[str, Path] = {}
        self.objects_beside: dict[str, Path] = {}
        self.blobs_beside: set[str] = set()
        self.kept_elsewhere: set[str] = set()
        self.reads_git_lfs = True
        self._held: dict[str, Path | None] = {}
        self._lfs_store: Path | None | bool = False

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
        data, more = self._stream(rel, self.opts.max_file_bytes)
        if not more:
            if data:
                yield 0, data.replace(b"\x00", b"").decode("utf-8", "replace")
            return
        sha = self._sha_by_path[rel]
        size = self._size(sha)
        if size is None:
            self.read_errors.append(rel)
        ext = _ext(rel)
        if size is None or (ext not in SOURCE_EXTS and not self.content_was_read(ext, data)):
            if size is not None:
                self.read_in_part.add(rel)
            text = self.read_text(rel)
            if text:
                yield 0, text
            return
        read = 0
        try:
            proc = self._cat_file(sha)
            with proc:
                def chunk(n: int) -> bytes:
                    nonlocal read
                    data = proc.stdout.read(n) or b""
                    read += len(data)
                    return data
                yield from stream_windows(chunk, size, self.opts.max_file_bytes)
        except (OSError, subprocess.SubprocessError):
            self.read_errors.append(rel)
            return
        if read < size:
            self.read_errors.append(rel)

    def local_object(self, sha: str, data: bytes | None = None) -> Path | None:
        """Find the local Git LFS object a stored version names. Takes the blob id and, when at
        hand, its bytes. Returns the object's path, or None when the version names none or its
        object is not kept here."""
        if sha in self._held:
            return self._held[sha]
        data = self.read_ahead.get(sha) if data is None else data
        if not data or lfs.named_object(data) is None:
            return None
        if self._lfs_store is False:
            self._lfs_store = lfs.store_of(self.root)
        self._held[sha] = lfs.local_object(self._lfs_store, data) if self._lfs_store else None
        return self._held[sha]

    def read_beside(self) -> HistoryTarget | None:
        """Build the target that reads what a checkout of these versions also holds: the Git LFS
        object of a version read as its own bytes, and the bytes of one read as its object. Returns
        it, or None when there is nothing more to read."""
        return _ReadBeside(self) if self.objects_beside or self.blobs_beside else None

    def _size(self, sha: str) -> int | None:
        """Ask the store for a version's size. Takes the blob id. Returns the size in bytes, or None
        when git could not say."""
        if self.objects.get(sha):
            try:
                return os.stat(self.objects[sha]).st_size
            except OSError:
                return None
        if sha in self.sizes:
            return self.sizes[sha]
        res = own_view(self.root, ["cat-file", "-s", sha])
        if res is None or res.returncode != 0:
            return None
        try:
            self.sizes[sha] = int((res.stdout or "").strip())
        except ValueError:
            return None
        return self.sizes[sha]

    def _cat_file(self, sha: str):
        """Stream the stored blob `sha`, as the walk that named it read the store: replace refs off.
        Raises OSError when git could not start or refused the command."""
        if self.objects.get(sha):
            return _ObjectStream(self.objects[sha])
        proc = open_stdout(Path(self.root), ["--no-replace-objects", "cat-file", "blob", sha])
        if proc is None:
            raise OSError(f"git could not read stored blob {sha}")
        return proc

    def _stream(self, rel: str, cap: int) -> tuple[bytes | None, bool]:
        """Read at most `cap` bytes of a stored version, or of the Git LFS object read in its place.
        Takes the path and the cap. Returns the bytes and whether there were more, or None when the
        version could not be read."""
        sha = self._sha_by_path.get(rel)
        if sha is None:
            return None, False
        if self.reads_git_lfs and sha not in self.objects:
            data, more = self._stream_blob(rel, sha, max(cap, lfs.POINTER_MAX_BYTES + 1))
            held = self.local_object(sha, data) if data else None
            if held is None or len(data) > lfs.POINTER_MAX_BYTES:
                if held is not None:
                    self.objects_beside[rel] = held
                elif data and lfs.checked_out_object(data) is not None:
                    self.kept_elsewhere.add(rel)
                return (data[:cap], more or len(data) > cap) if data else (data, more)
            self.objects[sha] = held
            if not lfs.only_a_pointer(data):
                self.blobs_beside.add(sha)
        return self._stream_blob(rel, sha, cap)

    def _stream_blob(self, rel: str, sha: str, cap: int) -> tuple[bytes | None, bool]:
        """Read at most `cap` bytes of one stored version. Takes the path, the blob id and the cap.
        Returns the bytes and whether there were more, or None when it could not be read."""
        if sha in self.read_ahead and sha not in self.objects:
            data = self.read_ahead[sha]
            return data[:cap], len(data) > cap
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


class _ReadBeside(HistoryTarget):
    """Read what a checkout of some stored versions holds besides what was read for them, each under
    its version's path."""

    def __init__(self, origin: HistoryTarget):
        """Build the reader. Takes the target whose versions were read."""
        paths = set(origin.objects_beside) | {rel for rel in origin.iter_files()
                                              if origin.sha_for(rel) in origin.blobs_beside}
        super().__init__(origin.root, origin.display, origin.opts,
                         {rel: [origin.sha_for(rel)] for rel in paths})
        self.source = origin.source
        self.reads_git_lfs = False
        self.merge_scope: list[str] = []
        self.objects = {origin.sha_for(rel): path for rel, path in origin.objects_beside.items()}
        self.read_ahead = origin.read_ahead
        self.sizes = origin.sizes
        self.read_errors = origin.read_errors
        self.read_in_part = origin.read_in_part
