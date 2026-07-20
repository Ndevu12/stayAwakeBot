#!/usr/bin/env python3
"""Git plumbing — a shared subprocess runner + read-only queries + evil-merge analysis,
split per concern under one package but exposed as ONE flat API so callers are unchanged:

    from stayawake.lib import git
    git.file_at(repo, sha, path)   git.evil_merge_paths(repo, merge)   git.run_ok(repo, args)

Submodules:
  run     — the shared runner: run / run_ok (checked) / stdout (read helper)
  auth    — credential-safe GitHub HTTPS (github_https_auth)
  query   — read-only queries (file_at, file_commits, origin_slug, ref_exists, …)
  merge   — evil-merge analysis (merge_commits, evil_merge_paths)
  write   — mutations (add_worktree, stage_all, commit_fix, push_branch, …)
"""
from stayawake.lib.git.run import run, run_ok, stdout
from stayawake.lib.git.auth import github_https_auth
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
    list_tree,
    tracked,
    tracked_under,
    file_commits,
    introduced_added_text,
    commit_meta,
    remote_has_branch,
)
from stayawake.lib.git.merge import merge_commits, evil_merge_paths
from stayawake.lib.git.write import (
    add_worktree,
    remove_worktree,
    stage_all,
    unstage_cached,
    commit_fix,
    CommitResult,
    BOT_AUTHOR,
    push_branch,
    delete_remote_branch,
    format_patch,
    fetch,
    delete_branch,
)

__all__ = [
    "run", "run_ok", "stdout", "github_https_auth",
    "is_git_repo", "slug_from_url", "origin_slug", "default_branch", "ref_exists",
    "parents", "changed_paths", "path_exists_at", "file_at", "list_tree", "tracked", "tracked_under",
    "file_commits", "introduced_added_text", "commit_meta", "remote_has_branch",
    "merge_commits", "evil_merge_paths",
    "add_worktree", "remove_worktree", "stage_all", "unstage_cached",
    "commit_fix", "CommitResult", "BOT_AUTHOR", "push_branch", "delete_remote_branch",
    "format_patch", "fetch", "delete_branch",
]
