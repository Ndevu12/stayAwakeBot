#!/usr/bin/env python3
"""Put the operator's uncommitted work on a local branch of its own, once it is clean."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import run, run_ok, stdout
from stayawake.utils import scratch

BRANCH_PREFIX = "saw/uncommitted-"
_BATCH = 200
MESSAGE = ("saw: the uncommitted working tree, after the cleanup\n\n"
           "What the working tree held that was not committed, as it stands once the payload has "
           "been removed. This branch is local and is never pushed.\n")


@dataclass(frozen=True)
class Preserved:
    """What a run put aside. `branch` is empty when nothing was, and `reason` names what stopped it."""

    branch: str = ""
    files: int = 0
    reason: str = ""

    def note(self) -> str:
        """Describe what was put aside, for the operator. Returns "" when nothing was."""
        if self.reason:
            return f"could not put your uncommitted work on a branch first: {self.reason}"
        if not self.branch:
            return ""
        return (f"{self.files} uncommitted file(s) saved on the local branch "
                f"{self.branch} — it is never pushed")


def uncommitted(repo: str | Path) -> list[str]:
    """The paths changed or added and not committed. Takes the repository. Returns the paths;
    ignored files are not among them."""
    out = stdout(repo, ["status", "--porcelain", "--untracked-files=all"])
    return [line[3:].strip() for line in out.splitlines() if line.strip()]


def preserve(repo: str | Path, remembered: list[str] | None = None) -> Preserved:
    """Commit the working tree to a local branch, leaving HEAD, the index and the files alone.

    Takes the repository and, optionally, the paths to stage; only those are staged. Returns what
    was put aside — an empty `Preserved` when none of them is still uncommitted, or one carrying
    `reason` when it could not be done.
    """
    changed = uncommitted(repo)
    if remembered is not None:
        changed = [p for p in changed if p in set(remembered)]
    if not changed:
        return Preserved()
    head = stdout(repo, ["rev-parse", "HEAD"]).strip()
    if not head:
        return Preserved(reason="this repository has no commit to branch from")
    index_dir = scratch.new_dir("the uncommitted-work branch")
    env = dict(os.environ, GIT_INDEX_FILE=str(index_dir / "index"))
    try:
        if not run_ok(repo, ["read-tree", head], env=env):
            return Preserved(reason="the current commit could not be read")
        if not _stage(repo, changed if remembered is not None else None, env):
            return Preserved(reason="the working tree could not be staged")
        res = run(repo, ["write-tree"], env=env)
        if res is None or res.returncode != 0:
            return Preserved(reason="the working tree could not be written")
        tree = (res.stdout or "").strip()
        res = run(repo, ["commit-tree", tree, "-p", head, "-m", MESSAGE])
        if res is None or res.returncode != 0:
            return Preserved(reason=f"the branch could not be committed ({_why(res)})")
        commit = (res.stdout or "").strip()
        branch = f"{BRANCH_PREFIX}{time.strftime('%Y-%m-%d-%H%M%S')}"
        if not run_ok(repo, ["update-ref", f"refs/heads/{branch}", commit]):
            return Preserved(reason="the branch could not be created")
        return Preserved(branch=branch, files=len(changed))
    finally:
        scratch.release_path(index_dir)


def _stage(repo: str | Path, paths: list[str] | None, env: dict) -> bool:
    """Stage the working tree into this run's own index.

    Takes the repository, the paths to stage — or None for all of them — and the environment
    naming that index. Returns whether every batch staged.
    """
    if paths is None:
        return run_ok(repo, ["add", "-A"], env=env)
    for start in range(0, len(paths), _BATCH):
        batch = paths[start:start + _BATCH]
        if not run_ok(repo, ["add", "-A", "--", *batch], env=env):
            return False
    return True


def _why(res) -> str:
    """The reason a git command gave. Takes its result. Returns a short line."""
    if res is None:
        return "git could not run"
    return ((res.stderr or "").strip().splitlines() or ["no reason given"])[0][:120]
