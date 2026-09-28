#!/usr/bin/env python3
"""A GitHub repo, shallow-cloned read-only into an ephemeral sandbox.

Never installs, builds, runs hooks, or opens an editor — clone-and-read only.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from stayawake.lib import git as gitutil
from stayawake.utils import scratch
from stayawake.bots.security.targets.base import Target, ScanOptions

_CLONE_TIMEOUT = 300


class RemoteRepoTarget(Target):
    source = "remote"

    def __init__(self, slug: str, opts: ScanOptions, token: str | None = None):
        self._tmp = scratch.new_dir("a remote scan")
        super().__init__(self._tmp / "repo", slug, opts)
        self._slug = slug
        self._token = token

    def clone(self) -> bool:
        def _attempt(url, env):
            return gitutil.run(None, ["clone", "--depth", str(self.opts.remote_clone_depth),
                                      "--no-tags", "--config", "core.hooksPath=/dev/null", url,
                                      str(self.root)],
                               env=env, timeout=_CLONE_TIMEOUT, context=gitutil.OPERATOR_PUSH)
        r = gitutil.run_remote_git(self._slug, self._token, _attempt)
        return r is not None and r.returncode == 0

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)
