#!/usr/bin/env python3
"""Git write operations — every command that MUTATES a repository or a remote, one file per
concern, all built on the shared checked runner (`run_ok`) so a failure is never swallowed:
"""
from stayawake.lib.git.write.worktree import add_worktree, remove_worktree
from stayawake.lib.git.write.stage import stage_all, unstage_cached
from stayawake.lib.git.write.commit import commit_fix, CommitResult, BOT_AUTHOR
from stayawake.lib.git.write.push import push_branch, push_branch_result, PushResult, delete_remote_branch
from stayawake.lib.git.write.patch import format_patch
from stayawake.lib.git.write.fetch import fetch
from stayawake.lib.git.write.branch import delete_branch
from stayawake.lib.git.write.capture import capture_bundle, BundleResult
from stayawake.lib.git.write.sign import (SigningStatus, signing_status, signing_available,
                                          signing_env, signing_args, sign_flags)

__all__ = [
    "add_worktree", "remove_worktree",
    "stage_all", "unstage_cached",
    "commit_fix", "CommitResult", "BOT_AUTHOR",
    "push_branch", "push_branch_result", "PushResult", "delete_remote_branch",
    "format_patch",
    "fetch",
    "delete_branch",
    "capture_bundle", "BundleResult",
    "SigningStatus", "signing_status", "signing_available", "signing_env", "signing_args",
    "sign_flags",
]
