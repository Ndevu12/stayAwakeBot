#!/usr/bin/env python3
"""Staging-area operations — stage the applied fix, and untrack a path that must not be
committed (the quarantine backup dir)."""
from __future__ import annotations

from pathlib import Path

from stayawake.core.git.run import run_ok


def stage_all(repo: str | Path) -> bool:
    """`git add -A` — stage every change in the worktree. Checked: the caller aborts rather
    than committing an unstaged (empty/partial) tree."""
    return run_ok(repo, ["add", "-A"])


def unstage_cached(repo: str | Path, pathspec: str | Path) -> bool:
    """Untrack `pathspec` from the index (`git rm -r --cached --ignore-unmatch`) without
    deleting it on disk — git only ignores UNTRACKED paths, so a pre-existing tracked
    quarantine dir must be untracked before staging. `--ignore-unmatch` makes it a no-op
    (exit 0) when nothing matches; the caller confirms the result with `tracked_under`."""
    return run_ok(repo, ["rm", "-r", "--cached", "--ignore-unmatch", str(pathspec)])
