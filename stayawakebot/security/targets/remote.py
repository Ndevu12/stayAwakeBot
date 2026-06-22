#!/usr/bin/env python3
"""A GitHub repo, shallow-cloned read-only into an ephemeral sandbox.

Never installs, builds, runs hooks, or opens an editor — clone-and-read only.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from stayawakebot.security.targets.base import Target, ScanOptions


class RemoteRepoTarget(Target):
    source = "remote"

    def __init__(self, slug: str, opts: ScanOptions, token: str | None = None):
        self._tmp = Path(tempfile.mkdtemp(prefix="sec-scan-"))
        super().__init__(self._tmp / "repo", slug, opts)
        self._slug = slug
        self._token = token

    def clone(self) -> bool:
        url = f"https://github.com/{self._slug}.git"
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_EDITOR="true")
        if self._token:
            url = f"https://x-access-token:{self._token}@github.com/{self._slug}.git"
        try:
            r = subprocess.run(
                ["git", "clone", "--depth", str(self.opts.remote_clone_depth), "--no-tags",
                 "--config", "core.hooksPath=/dev/null", url, str(self.root)],
                capture_output=True, text=True, timeout=300, env=env, check=False)
            return r.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)
