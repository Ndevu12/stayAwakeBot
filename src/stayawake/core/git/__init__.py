#!/usr/bin/env python3
"""Git plumbing — a shared subprocess runner + read-only queries + evil-merge analysis,
split per concern under one package but exposed as ONE flat API so callers are unchanged:

    from stayawake.core import git
    git.file_at(repo, sha, path)   git.evil_merge_paths(repo, merge)   git.run_ok(repo, args)

Submodules:
  run     — the shared runner: run / run_ok (checked) / stdout (read helper)
  auth    — credential-safe GitHub HTTPS (github_https_auth)
  query   — read-only queries (file_at, file_commits, is_git_repo, tracked, …)
  merge   — evil-merge analysis (merge_commits, evil_merge_paths)

Write operations (worktree / commit / push / …) live in `core.git.write`.
"""
from stayawake.core.git.run import run, run_ok, stdout
from stayawake.core.git.auth import github_https_auth
from stayawake.core.git.query import (
    is_git_repo,
    parents,
    changed_paths,
    path_exists_at,
    file_at,
    tracked,
    file_commits,
    introduced_added_text,
    commit_meta,
)
from stayawake.core.git.merge import merge_commits, evil_merge_paths

__all__ = [
    "run", "run_ok", "stdout", "github_https_auth",
    "is_git_repo", "parents", "changed_paths", "path_exists_at", "file_at", "tracked",
    "file_commits", "introduced_added_text", "commit_meta",
    "merge_commits", "evil_merge_paths",
]
