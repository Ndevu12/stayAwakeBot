#!/usr/bin/env python3
"""A GitHub repo, shallow-cloned read-only into an ephemeral sandbox.

Never installs, builds, runs hooks, or opens an editor — clone-and-read only.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from stayawake.lib import git as gitutil
from stayawake.bots.security.targets.base import Target, ScanOptions


class RemoteRepoTarget(Target):
    source = "remote"

    def __init__(self, slug: str, opts: ScanOptions, token: str | None = None):
        self._tmp = Path(tempfile.mkdtemp(prefix="sec-scan-"))
        super().__init__(self._tmp / "repo", slug, opts)
        self._slug = slug
        self._token = token

    def clone(self) -> bool:
        # Token (if any) is supplied via GIT_ASKPASS, never in the URL/argv.
        try:
            with gitutil.github_https_auth(self._token) as (prefix, env):
                r = subprocess.run(
                    ["git", "clone", "--depth", str(self.opts.remote_clone_depth), "--no-tags",
                     "--config", "core.hooksPath=/dev/null",
                     f"{prefix}{self._slug}.git", str(self.root)],
                    capture_output=True, text=True, timeout=300, env=env, check=False)
            return r.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)
