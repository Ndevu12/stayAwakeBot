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


@dataclass
class ScanOptions:
    exclude_dirs: set[str] = field(default_factory=lambda: {
        ".git", "node_modules", ".next", "dist", "build", ".malware-quarantine"})
    max_file_bytes: int = 2_000_000
    remote_clone_depth: int = 50


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

    def read_text(self, rel: str) -> str | None:
        raw = self.read_bytes(rel)
        if raw is None or b"\x00" in raw[:8192]:
            return None
        return raw.decode("utf-8", errors="replace")

    def cleanup(self) -> None:
        pass

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()
