#!/usr/bin/env python3
"""Read a repository that has no working tree, through the git queries the scan already uses."""
from __future__ import annotations

from typing import Iterator

from stayawake.lib.git.objects import blob, blob_sizes
from stayawake.lib.git.query import (GITLINK_MODE, SYMLINK_MODE, Unread, entries_at,
                                    holds_a_commit)
from stayawake.lib.git.run import open_stdout

from .base import (SOURCE_EXTS, TRUNCATION_MARKER, Target, _ext, stream_runs_of_text,
                   stream_windows, text_of)

_CHUNK = 1 << 20


class BareTreeTarget(Target):
    """Read the files the repository holds at HEAD."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._files: dict[str, str] | None = None
        self._sizes: dict[str, int] = {}

    def iter_files(self) -> Iterator[str]:
        if self.include_only is not None:
            yield from self.include_only
            return
        if self._walk_cache is None:
            prefix = f"{self.within.strip('/')}/" if self.within else ""
            self._walk_cache = [rel for rel in self._held()
                                if not prefix or rel == prefix[:-1] or rel.startswith(prefix)]
        yield from self._walk_cache

    def read_bytes(self, rel: str, limit: int | None = None) -> bytes | None:
        return self._bytes(rel, limit=limit)

    def read_text(self, rel: str) -> str | None:
        ext = _ext(rel)
        size = self._size_of(rel)
        if size is None:
            return None
        if size > self.opts.max_file_bytes and ext not in SOURCE_EXTS:
            return None
        raw = self._bytes(rel, whole=True)
        if raw is None:
            return None
        return text_of(raw, ext)

    def read_source_windows(self, rel: str) -> Iterator[tuple[int, str]]:
        ext = _ext(rel)
        size = self._size_of(rel)
        if size is None:
            return
        if size <= self.opts.max_file_bytes:
            text = self.read_text(rel) if ext in SOURCE_EXTS else self._nonsource_scan_text(rel)
            if text is not None:
                yield (0, text)
            return
        proc = self._open(rel)
        if proc is None:
            return
        try:
            sniff = proc.stdout.read(self.BINARY_SNIFF_BYTES)
        finally:
            self._close(proc)
        proc = self._open(rel)
        if proc is None:
            return
        was_read = self.content_was_read(ext, sniff)
        walk = stream_windows if was_read else stream_runs_of_text
        try:
            yield from walk(proc.stdout.read, size, self.opts.max_file_bytes)
        finally:
            self._close(proc)

    def _held(self) -> dict[str, str]:
        """List the files HEAD holds. Returns each path with its object id. An unreadable list is
        empty, and recorded."""
        if self._files is None:
            self._files = self._load()
        return self._files

    def _load(self) -> dict[str, str]:
        present = holds_a_commit(self.root)
        if present is None:
            self.read_errors.append(str(Unread("the files of HEAD")))
            return {}
        if not present:
            return {}
        try:
            held = entries_at(self.root, "HEAD")
        except Unread as err:
            self.read_errors.append(str(err))
            return {}
        files = {path: oid for path, (mode, oid) in held.items()
                 if mode not in (GITLINK_MODE, SYMLINK_MODE)
                 and not any(part in self.opts.exclude_dirs for part in path.split("/")[:-1])}
        sizes = blob_sizes(self.root, list(files.values()))
        if sizes is None:
            self.read_errors.append(str(Unread("the files of HEAD")))
            return {}
        self._sizes = sizes
        return files

    def _size_of(self, rel: str) -> int | None:
        """The size of the file HEAD holds at `rel`. Takes the path. Returns the size, or None when
        the path is absent or its size could not be read."""
        oid = self._held().get(rel)
        if oid is None:
            return None
        size = self._sizes.get(oid)
        if size is None:
            self.read_errors.append(f"{rel}: the file could not be read")
            return None
        return size

    def _bytes(self, rel: str, limit: int | None = None, *, whole: bool = False) -> bytes | None:
        """Read the bytes HEAD holds at `rel`. Takes the path, a read limit, and whether a file
        over the size cap is still read. Returns the bytes, or None when the path is absent,
        skipped for size, or could not be read."""
        size = self._size_of(rel)
        if size is None:
            return None
        if not whole and limit is None and size > self.opts.max_file_bytes:
            return None
        oid = self._held()[rel]
        if limit is not None and size > limit:
            return self._prefix(rel, oid, limit)
        if whole and size > self.opts.max_file_bytes:
            return self._ends(rel, max(1, self.opts.max_file_bytes // 2))
        data = blob(self.root, oid)
        if data is None:
            self.read_errors.append(f"{rel}: the file could not be read")
            return None
        return data[:limit] if limit else data

    def _prefix(self, rel: str, oid: str, limit: int) -> bytes | None:
        """Read the first bytes of a stored blob. Takes the path, the object id and how many.
        Returns them, or None when git could not."""
        proc = self._open(rel, oid)
        if proc is None:
            return None
        try:
            return proc.stdout.read(limit)
        except OSError:
            self.read_errors.append(f"{rel}: the file could not be read")
            return None
        finally:
            self._close(proc)

    def _ends(self, rel: str, half: int) -> bytes | None:
        """Read a head and a tail of a stored blob. Takes the path and the size of each end.
        Returns them joined by the truncation marker, or None when git could not."""
        proc = self._open(rel)
        if proc is None:
            return None
        try:
            head = proc.stdout.read(half)
            tail = b""
            while True:
                chunk = proc.stdout.read(_CHUNK)
                if not chunk:
                    break
                tail = (tail + chunk)[-half:]
            return head + TRUNCATION_MARKER + tail
        except OSError:
            self.read_errors.append(f"{rel}: the file could not be read")
            return None
        finally:
            self._close(proc)

    def _open(self, rel: str, oid: str | None = None):
        """Start reading the blob HEAD holds at `rel`. Takes the path and, when known, the object
        id. Returns the process, or None when git could not start."""
        oid = oid if oid is not None else self._held().get(rel)
        if oid is None:
            return None
        proc = open_stdout(self.root, ["cat-file", "blob", oid])
        if proc is None or proc.stdout is None:
            self.read_errors.append(f"{rel}: the file could not be read")
            return None
        return proc

    @staticmethod
    def _close(proc) -> None:
        proc.stdout.close()
        proc.kill()
        proc.wait()
