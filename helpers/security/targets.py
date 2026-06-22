#!/usr/bin/env python3
"""Scan targets — a source-agnostic surface the matchers read from.

LocalRepoTarget wraps a path already on disk; RemoteRepoTarget shallow-clones a
GitHub repo into an ephemeral sandbox (read-only: no install, no build, no
checkout of hooks/submodules, never opened in an editor). Both expose the same
tiny interface so the scanner is decoupled from where code comes from (DIP).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
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
    """Base: a directory tree to scan. `repo_root` is where git ops run."""

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
                ap = Path(dirpath) / fn
                yield str(ap.relative_to(self.root))

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
        if raw is None or b"\x00" in raw[:8192]:   # NUL byte ⇒ treat as binary
            return None
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

    def cleanup(self) -> None:  # no-op for local
        pass

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()


class LocalRepoTarget(Target):
    source = "local"


class RemoteRepoTarget(Target):
    """owner/repo shallow-cloned into a temp dir; cleaned up on exit."""

    source = "remote"

    def __init__(self, slug: str, opts: ScanOptions, token: str | None = None):
        self._tmp = Path(tempfile.mkdtemp(prefix="sec-scan-"))
        super().__init__(self._tmp / "repo", slug, opts)
        self._slug = slug
        self._token = token
        self._cloned = False

    def clone(self) -> bool:
        url = f"https://github.com/{self._slug}.git"
        env = dict(os.environ)
        # No credential prompts, no hook execution, no editor.
        env.update(GIT_TERMINAL_PROMPT="0", GIT_EDITOR="true")
        if self._token:
            url = f"https://x-access-token:{self._token}@github.com/{self._slug}.git"
        try:
            r = subprocess.run(
                ["git", "clone", "--depth", str(self.opts.remote_clone_depth),
                 "--no-tags", "--config", "core.hooksPath=/dev/null", url, str(self.root)],
                capture_output=True, text=True, timeout=300, env=env, check=False,
            )
            self._cloned = r.returncode == 0
            return self._cloned
        except (subprocess.SubprocessError, OSError):
            return False

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)
