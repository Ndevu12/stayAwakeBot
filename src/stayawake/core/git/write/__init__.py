#!/usr/bin/env python3
"""Git write operations — every command that MUTATES a repository or a remote, one file per
concern, all built on the shared checked runner (`run_ok`) so a failure is never swallowed:

    worktree — add_worktree / remove_worktree   (isolated fix worktree)
    stage    — stage_all / unstage_cached        (the index)
    commit   — commit_fix / CommitResult / BOT_AUTHOR   (never a phantom empty branch)
    push     — push_branch / delete_remote_branch (publish / discard, credential-safe)
    patch    — format_patch                       (the no-write floor)
    fetch    — fetch                              (refresh the base)
    branch   — delete_branch                      (discard the fix branch)

Exposed flat via `core.git` too, so callers use `git.commit_fix(...)`, `git.push_branch(...)`."""
from stayawake.core.git.write.worktree import add_worktree, remove_worktree
from stayawake.core.git.write.stage import stage_all, unstage_cached
from stayawake.core.git.write.commit import commit_fix, CommitResult, BOT_AUTHOR
from stayawake.core.git.write.push import push_branch, delete_remote_branch
from stayawake.core.git.write.patch import format_patch
from stayawake.core.git.write.fetch import fetch
from stayawake.core.git.write.branch import delete_branch

__all__ = [
    "add_worktree", "remove_worktree",
    "stage_all", "unstage_cached",
    "commit_fix", "CommitResult", "BOT_AUTHOR",
    "push_branch", "delete_remote_branch",
    "format_patch",
    "fetch",
    "delete_branch",
]
