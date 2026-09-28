#!/usr/bin/env python3
"""Git plumbing — a shared subprocess runner + read-only queries + evil-merge analysis,
split per concern under one package but exposed as ONE flat API so callers are unchanged:

    from stayawake.lib import git
    git.file_at(repo, sha, path)   git.evil_merge_paths(repo, merge)   git.run_ok(repo, args)

Submodules:
  run     — the one git runner: run / run_ok (checked) / stdout, under a context (contexts)
  borrowed — a saw-owned repository over the operator's objects (merge-tree, materialise)
  auth    — credential-safe GitHub HTTPS (github_https_auth)
  query   — read-only queries (file_at, file_commits, origin_slug, ref_exists, …)
  merge   — evil-merge analysis (merge_commits, evil_merge_paths)
  write   — mutations (add_worktree, stage_all, commit_fix, push_branch, …)
"""
from stayawake.lib.git.run import (run, run_ok, stdout, UNTRUSTED, SAW_OWNED, OPERATOR_PUSH,
                                   OPERATOR_CONFIG, GitRefused)
from stayawake.lib.git.auth import github_https_auth, github_remote, run_remote_git
from stayawake.lib.git.query import (
    is_git_repo,
    slug_from_url,
    origin_slug,
    default_branch,
    ref_exists,
    parents,
    changed_paths,
    path_exists_at,
    file_at,
    tree_entry,
    list_tree,
    tracked,
    tracked_under,
    file_commits,
    introduced_added_text,
    commit_meta,
    remote_has_branch,
    is_ancestor,
    branches_matching,
    branches_carrying,
    branch_refs,
    branch_name_of,
    fetch_refs,
    FetchResult,
    commit_count,
    ref_counts,
    remote_branches_matching,
)
from stayawake.lib.git.merge import merge_commits, evil_merge_paths, clean_merge_blob, borrowed_or_none
from stayawake.lib.git.borrowed import borrow, Borrowed, BorrowError
from stayawake.lib.git.write import (
    add_worktree,
    remove_worktree,
    release_worktree,
    stage_all,
    unstage_cached,
    commit_fix,
    CommitResult,
    BOT_AUTHOR,
    push_branch,
    push_branch_result,
    PushResult,
    delete_remote_branch,
    format_patch,
    fetch,
    delete_branch,
)

__all__ = [
    "run", "run_ok", "stdout", "UNTRUSTED", "SAW_OWNED", "OPERATOR_PUSH", "OPERATOR_CONFIG",
    "GitRefused", "github_https_auth", "github_remote", "run_remote_git",
    "is_git_repo", "slug_from_url", "origin_slug", "default_branch", "ref_exists",
    "parents", "changed_paths", "path_exists_at", "file_at", "tree_entry", "list_tree", "tracked", "tracked_under",
    "file_commits", "introduced_added_text", "commit_meta", "remote_has_branch", "is_ancestor",
    "branches_matching", "branches_carrying", "branch_refs", "branch_name_of",
    "fetch_refs", "FetchResult",
    "remote_branches_matching", "ref_safe_segment", "choose_branch", "commit_count", "ref_counts",
    "merge_commits", "evil_merge_paths", "clean_merge_blob", "borrowed_or_none",
    "borrow", "Borrowed", "BorrowError",
    "add_worktree", "remove_worktree", "release_worktree", "stage_all", "unstage_cached",
    "commit_fix", "CommitResult", "BOT_AUTHOR", "push_branch", "push_branch_result", "PushResult",
    "delete_remote_branch",
    "format_patch", "fetch", "delete_branch",
]

from stayawake.lib.git.naming import ref_safe_segment, choose_branch  # noqa: E402
