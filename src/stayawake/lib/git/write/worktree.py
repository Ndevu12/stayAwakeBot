#!/usr/bin/env python3
"""Creating and tearing down a throwaway worktree, and its branch."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import run_ok


def prune_worktrees(repo: str | Path) -> bool:
    """Drop the registrations of worktrees whose directory is gone. Takes the repo. Returns whether
    git ran."""
    return run_ok(repo, ["worktree", "prune"])


def add_worktree(repo: str | Path, path: str | Path, branch: str, baseref: str) -> bool:
    """Create a worktree on a fresh branch. Takes the repo, the path, the branch and the ref to
    reset it to. Drops stale registrations first. Returns whether git created it."""
    prune_worktrees(repo)
    return run_ok(repo, ["worktree", "add", "-f", "-B", branch, str(path), baseref])


def remove_worktree(repo: str | Path, path: str | Path) -> bool:
    """Tear down a worktree, leaving its branch. Takes the repo and the path. Returns whether git
    removed it."""
    removed = run_ok(repo, ["worktree", "remove", "--force", str(path)])
    prune_worktrees(repo)
    return removed


def release_worktree(repo: str | Path):
    """Build the teardown for a worktree under this repo. Takes the repo. Returns a callable that
    takes the path and returns "" when the worktree is gone, else why it is not."""
    def teardown(path: Path) -> str:
        remove_worktree(repo, path)
        return "" if not Path(path).exists() else f"git would not remove the worktree at {path}"
    return teardown
