#!/usr/bin/env python3
"""Capture the fix commit as a git-am-able patch — the no-write floor of the remediation
ladder, so a read-only run never loses the work when the branch can't be pushed."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.borrowed import borrow
from stayawake.lib.git.run import SAW_OWNED, run
from stayawake.lib.git.write.transfer import resolved
from stayawake.lib.git.write.worktree import held_checkout


def _format(where: str | Path, commit: str) -> str | None:
    res = run(where, ["format-patch", "-1", commit, "--stdout"], context=SAW_OWNED)
    if res is None or res.returncode != 0 or not res.stdout.strip():
        return None
    return res.stdout


def format_patch(repo: str | Path, ref: str = "HEAD") -> str | None:
    """The single commit `ref` as a `git am`-able patch (text), or None if there is no such commit,
    git failed or the patch is empty. Rendered in a saw-owned repository: the fix checkout, or
    one borrowing `repo`'s objects."""
    if held_checkout(repo) is not None:
        return _format(repo, ref)
    commit = resolved(repo, ref)
    if not commit:
        return None
    try:
        with borrow(repo) as borrowed:
            return _format(borrowed.path, commit)
    except OSError:
        return None
