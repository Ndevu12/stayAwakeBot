#!/usr/bin/env python3
"""Scan targets and the options that control a scan.

`ScanOptions` carries the per-run settings; `Target` is the interface a scanner reads a tree
through, so local and cloned repositories look the same to every matcher.
"""
from __future__ import annotations

import os
import stat as _stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


CODE_EXTS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
    ".sh", ".bash", ".zsh", ".py", ".rb", ".php", ".go", ".rs",
    ".bat", ".cmd", ".ps1", ".psm1", ".json",
}

SOURCE_EXTS = CODE_EXTS | {
    ".vue", ".svelte", ".md", ".yml", ".yaml", ".html", ".htm", ".css", ".map",
}


_SOURCE_WINDOW_OVERLAP = 65_536

_MAX_INTERIOR_SCAN_BYTES = 64_000_000


def _ext(rel: str) -> str:
    i = rel.rfind(".")
    return rel[i:].lower() if i != -1 else ""


@dataclass
class ScanOptions:
    exclude_dirs: set[str] = field(default_factory=lambda: {
        ".git", "node_modules", ".next", "dist", "build", ".malware-quarantine"})
    max_file_bytes: int = 2_000_000
    remote_clone_depth: int = 50
    scan_build_outputs: bool = False
    dependency_advisories: bool = True
    external_audit: bool = False
    deep: bool = False
    history: bool = False        # also read what the repository still stores on other refs


class Target:
    source = "local"

    def __init__(self, root: str | Path, display: str, opts: ScanOptions,
                 include_only: tuple[str, ...] | None = None):
        self.root = Path(root)
        self.display = display
        self.opts = opts
        self.include_only = include_only
        self._walk_cache: list[str] | None = None
        self.read_errors: list[str] = []
        self.coverage_notes: list[str] = []

    @property
    def repo_root(self) -> Path:
        return self.root

    def iter_files(self) -> Iterator[str]:
        if self.include_only is not None:       #a pre-discovered file-chunk — no re-walk
            yield from self.include_only
            return
        if self._walk_cache is None:            # walk once, memoize (byte-identical replay after)
            cache: list[str] = []
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in self.opts.exclude_dirs]
                for fn in filenames:
                    cache.append(str((Path(dirpath) / fn).relative_to(self.root)))
            self._walk_cache = cache
        yield from self._walk_cache

    def _note_unreadable(self, name: str, p: Path, exc: OSError) -> None:
        """A file present but unreadable is a scan GAP → recorded so the run fails CLOSED — EXCEPT a
        SYMLINK, whose read failure is a loop (ELOOP), an escape, or a broken/dangling target: a benign
        skip, not scannable content (an escaping link is surfaced separately by the symlink matcher).
        Recording a symlink cycle as an 'unreadable file' would wrongly fail the whole scan."""
        try:
            if p.is_symlink():
                return                            # symlink loop/escape/broken → benign skip
        except OSError:
            pass                                  # can't tell (e.g. EACCES on 3.11) → be conservative
        self.read_errors.append(f"{name}: {type(exc).__name__}")   # genuine gap → fail CLOSED

    def read_bytes(self, rel: str, limit: int | None = None) -> bytes | None:
        p = self.root / rel
        try:
            st = p.stat()
        except OSError:
            return None                           # can't stat (vanished / race) — treat as absent
        if not _stat.S_ISREG(st.st_mode):
            return None                           # FIFO/socket/device → benign skip: a blocking open()
            #                                       would HANG the scan forever, and there's no static
        if limit is None and st.st_size > self.opts.max_file_bytes:
            return None                           # policy skip (too large) — a benign skip
        try:
            with p.open("rb") as fh:
                return fh.read(limit) if limit else fh.read()
        except OSError as exc:
            # Present but unreadable — a scan GAP, not a benign skip. Record it (fail closed).
            self._note_unreadable(rel, p, exc)
            return None

    def _nonsource_scan_text(self, rel: str, p: Path, size: int) -> str | None:
        """A NUL-stripped, bounded head+tail of a NON-source file for the confirmed content tier only.
        A payload under a non-source extension (an oversized `.bin`, a NUL-laden fake `.png`) is skipped
        by ``read_text``; this lets the cheap line-local content regexes still see a bounded window of
        it. Head+tail (not head-only) so an appended payload is covered too, matching the oversized
        source read. NUL bytes are stripped so 'binary' bytes decode to scannable text."""
        if size > self.opts.max_file_bytes:
            raw = self._head_tail(p, max(1, self.opts.max_file_bytes // 2))
        else:
            raw = self.read_bytes(rel)
        if not raw:
            return None
        return raw.replace(b"\x00", b"").decode("utf-8", errors="replace")

    def _head_tail(self, p: Path, half: int) -> bytes:
        """Read a bounded head+tail of an oversized file (payload is usually
        appended, so the tail matters) instead of skipping it wholesale."""
        try:
            with p.open("rb") as fh:
                head = fh.read(half)
                try:
                    fh.seek(-half, os.SEEK_END)
                except OSError:
                    fh.seek(0)
                tail = fh.read(half)
            return head + b"\n/*\xe2\x80\xa6stayawake-truncated\xe2\x80\xa6*/\n" + tail
        except OSError as exc:
            self._note_unreadable(p.name, p, exc)   # unreadable oversized file — a gap (unless a symlink)
            return b""

    # The rule read_text applies, exposed so nothing re-derives it — verify.py did, with its own
    # window, and every adversarial round walked through the gap between the two.
    BINARY_SNIFF_BYTES = 8192

    @classmethod
    def content_was_read(cls, ext: str, raw: bytes | None, oversized: bool) -> bool:
        """Did read_text() examine this file's content, given what it saw? ONE definition, two callers."""
        if raw is None:
            return False
        if oversized and ext not in SOURCE_EXTS:
            return False                          # genuinely large binary — skipped wholesale
        if b"\x00" in raw[:cls.BINARY_SNIFF_BYTES] and ext not in SOURCE_EXTS:
            return False                          # real binary asset
        return True

    def read_text(self, rel: str) -> str | None:
        p = self.root / rel
        ext = _ext(rel)
        try:
            st = p.stat()
        except FileNotFoundError:
            return None                           # vanished (race) — benign skip
        except OSError as exc:
            self._note_unreadable(rel, p, exc)    # present but unstattable — a gap (unless a symlink)
            return None
        if not _stat.S_ISREG(st.st_mode):
            return None                           # FIFO/socket/device → benign skip, never a blocking
        size = st.st_size
        if size > self.opts.max_file_bytes:
            if ext not in SOURCE_EXTS:
                return None                       # genuinely large binary — skip
            raw = self._head_tail(p, max(1, self.opts.max_file_bytes // 2))
        else:
            raw = self.read_bytes(rel)
            if raw is None:
                return None
        if b"\x00" in raw[:8192]:
            if ext in SOURCE_EXTS:
                raw = raw.replace(b"\x00", b"")
            else:
                return None                       # real binary asset
        return raw.decode("utf-8", errors="replace")

    def read_source_windows(self, rel: str) -> Iterator[tuple[int, str]]:
        """Yield ``(line_offset, text)`` chunks covering the WHOLE body of a source file.

        ``read_text`` truncates an oversized source file to head+tail, so the interior (offset
        ~1 MB .. size-1 MB) is unscanned — a payload buried there is invisible to every matcher. This reader streams the full file in overlapping windows
        so no interior region is skipped. It is for the CHEAP, line-local confirmed content-regex
        tier ONLY (ContentMatcher). The expensive whole-file density heuristic deliberately stays
        head/tail-bounded via ``read_text`` — do NOT route it through here (it is FP-prone on the
        large minified bundles this method now reads in full).

        Memory stays bounded: at most one window is resident (``max_file_bytes`` bytes), regardless
        of file size — a 500 MB source file is scanned in ~2 MB working-set chunks, never read whole.
        Total work is bounded too: files larger than ``_MAX_INTERIOR_SCAN_BYTES`` fall back to the
        head+tail read so a hostile target can't force unbounded scanning with one enormous file.
        ``line_offset`` is the count of newlines BEFORE the window's first byte, computed in the byte
        domain (a caller adds ``text.count("\\n", 0, match)`` to it for the absolute 1-based line).
        Small files (<= cap) yield exactly one ``(0, text)`` window equal to ``read_text`` — the
        common path is byte-for-byte unchanged (verdict-identical).
        """
        p = self.root / rel
        ext = _ext(rel)
        try:
            st = p.stat()
        except FileNotFoundError:
            return                                # vanished (race) — benign skip
        except OSError as exc:
            self._note_unreadable(rel, p, exc)    # unstattable — a gap (unless a symlink loop/escape)
            return
        if not _stat.S_ISREG(st.st_mode):
            return                                # FIFO/socket/device → benign skip (no blocking open,)
        size = st.st_size
        if ext not in SOURCE_EXTS:
            text = self._nonsource_scan_text(rel, p, size)
            if text is not None:
                yield (0, text)
            return
        if size <= self.opts.max_file_bytes:
            text = self.read_text(rel)
            if text is not None:
                yield (0, text)
            return
        if size > _MAX_INTERIOR_SCAN_BYTES:
            text = self.read_text(rel)
            if text is not None:
                yield (0, text)
            return
        window = self.opts.max_file_bytes
        step = max(1, window - min(_SOURCE_WINDOW_OVERLAP, window // 2))
        nl_before = 0
        pos = 0
        try:
            with p.open("rb") as fh:
                while pos < size:
                    fh.seek(pos)
                    raw = fh.read(window)
                    if not raw:
                        break
                    chunk = raw.replace(b"\x00", b"")
                    yield (nl_before, chunk.decode("utf-8", errors="replace"))
                    nl_before += raw.count(b"\n", 0, step)   # newlines we step past (byte domain — exact)
                    pos += step
        except OSError as exc:
            self._note_unreadable(rel, p, exc)    # unreadable oversized file — a gap (unless a symlink)
            return

    def cleanup(self) -> None:
        pass

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()
