#!/usr/bin/env python3
"""Worktree lifecycle — build the remediation in a throwaway worktree so the user's working
tree is never touched, and the fix branch ref persists after the worktree is torn down."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import run_ok


def add_worktree(repo: str | Path, path: str | Path, branch: str, baseref: str) -> bool:
    """Create a worktree at `path` on a fresh `branch` (force-reset to `baseref`). Checked —
    the caller aborts the fix if this fails rather than committing into a bad tree."""
    return run_ok(repo, ["worktree", "add", "-f", "-B", branch, str(path), baseref])


def remove_worktree(repo: str | Path, path: str | Path) -> bool:
    """Tear down the worktree at `path` (the branch ref survives, ready to review/push).
    Best-effort cleanup — returns False if git couldn't remove it, but never raises."""
    return run_ok(repo, ["worktree", "remove", "--force", str(path)])
