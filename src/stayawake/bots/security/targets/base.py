#!/usr/bin/env python3
"""Target base + scan options.

A Target is a directory tree the matchers read from. Subclasses differ only in
how the tree gets there (already on disk vs cloned). Same interface ⇒ the scanner
is decoupled from the source (DIP).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# Source/text extensions we always attempt to scan even when a file looks "binary"
# (NUL bytes) or exceeds the size cap — the worm hides in exactly these, so one NUL
# byte or 2 MB of padding must not buy it invisibility.
SOURCE_EXTS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
    ".json", ".vue", ".svelte", ".md", ".yml", ".yaml", ".sh", ".bash",
    ".py", ".rb", ".php", ".go", ".rs", ".html", ".htm", ".css", ".map",
}


def _ext(rel: str) -> str:
    i = rel.rfind(".")
    return rel[i:].lower() if i != -1 else ""


@dataclass
class ScanOptions:
    # Two kinds of exclusion, both deliberate (see docs/SECURITY_ARCHITECTURE.md → "Provenance is
    # not trust"):
    #  * BUILD OUTPUTS — "node_modules", ".next", "dist", "build": compiled/vendored artifacts where
    #    minification IS obfuscation, so the density heuristic there would be all false positives.
    #    This is a build-artifact trust decision, NOT a provenance one — `saw` never trusts an
    #    attestation; it just doesn't judge post-build shape. A payload minified into a bundle is a
    #    documented residual (obfuscation.py docstring), and settings can override this set to include
    #    them. Known loader FINGERPRINTS still match anywhere that IS traversed.
    #  * SELF-OUTPUT — "reports", "sab-patches", ".malware-quarantine": the scanner's own output
    #    (a report quotes a payload's evidence; a remediation patch/quarantine holds the removed
    #    payload lines), so scanning them self-triggers.
    exclude_dirs: set[str] = field(default_factory=lambda: {
        ".git", "node_modules", ".next", "dist", "build", ".malware-quarantine",
        "reports", "sab-patches"})
    max_file_bytes: int = 2_000_000
    remote_clone_depth: int = 50
    # Opt-in (config `scan_build_outputs: true`): also scan build outputs. When set, the service
    # un-prunes the build-output dirs above AND the obfuscation matcher runs its self-evident
    # construct checks (numeric array / exec sink / base64 / escape run) on generated paths — but
    # NOT the whole-file density heuristic (density is genuinely expected in bundles) — emitting a
    # `heuristic` `obfuscated-build-artifact` finding, never `confirmed`. Default off (FP-safe
    # defaults unchanged).
    scan_build_outputs: bool = False


class Target:
    source = "local"

    def __init__(self, root: str | Path, display: str, opts: ScanOptions):
        self.root = Path(root)
        self.display = display
        self.opts = opts

    @property
    def repo_root(self) -> Path:
        return self.root

    def iter_files(self) -> Iterator[str]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in self.opts.exclude_dirs]
            for fn in filenames:
                yield str((Path(dirpath) / fn).relative_to(self.root))

    def read_bytes(self, rel: str, limit: int | None = None) -> bytes | None:
        p = self.root / rel
        try:
            if limit is None and p.stat().st_size > self.opts.max_file_bytes:
                return None
            with p.open("rb") as fh:
                return fh.read(limit) if limit else fh.read()
        except OSError:
            return None

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
        except OSError:
            return b""

    def read_text(self, rel: str) -> str | None:
        p = self.root / rel
        ext = _ext(rel)
        try:
            size = p.stat().st_size
        except OSError:
            return None
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
                raw = raw.replace(b"\x00", b"")   # NUL-laden source is itself suspicious — scan anyway
            else:
                return None                       # real binary asset
        return raw.decode("utf-8", errors="replace")

    def cleanup(self) -> None:
        pass

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()
