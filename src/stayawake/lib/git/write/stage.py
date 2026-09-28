#!/usr/bin/env python3
"""Staging in a fix checkout saw made: stage the applied fix, and untrack a path that must not be
committed (the rollback store). Refused anywhere else."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import SAW_OWNED, run_ok
from stayawake.lib.git.write.worktree import held_checkout


def stage_all(repo: str | Path) -> bool:
    """`git add -A` in a fix checkout. Checked: the caller aborts rather than committing an
    unstaged (empty/partial) tree. False for a directory saw did not make a checkout in."""
    if held_checkout(repo) is None:
        return False
    return run_ok(repo, ["add", "-A"], context=SAW_OWNED)


def unstage_cached(repo: str | Path, pathspec: str | Path) -> bool:
    """Untrack `pathspec` from a fix checkout's index without deleting it on disk — git only
    ignores UNTRACKED paths, so a pre-existing tracked rollback store must be untracked before
    staging. A no-op when nothing matches; the caller confirms the result with `tracked_under`.
    False for a directory saw did not make a checkout in."""
    if held_checkout(repo) is None:
        return False
    return run_ok(repo, ["rm", "-r", "--cached", "--ignore-unmatch", "--", str(pathspec)],
                  context=SAW_OWNED)
