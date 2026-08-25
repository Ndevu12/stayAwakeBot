#!/usr/bin/env python3
"""`saw discard` — the inverse of fix: delete the auto-clean branch / close its PR, locally or on a remote."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.adapters import github_api
from stayawake.lib import git as gitutil
from stayawake.bots.security.pr.constants import FIX_BRANCH

def discard_branch(repo: Path) -> str:
    """Delete the local `security/auto-clean` branch and origin's copy, using the repo's own
    `origin` auth (SSH key / credential helper) — no GitHub API, so it works even when the
    API is unreachable. Deleting the remote branch auto-closes any PR opened from it."""
    slug = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    did: list[str] = []
    failed: list[str] = []
    # Fix branches are named per base now, so discard sweeps the family. The bare legacy name is
    # always included: a repo fixed by an older version keeps it forever otherwise.
    local = sorted(set(gitutil.branches_matching(repo, f"{FIX_BRANCH}*"))
                   | ({FIX_BRANCH} if gitutil.ref_exists(repo, f"refs/heads/{FIX_BRANCH}") else set()))
    remote = sorted(set(gitutil.remote_branches_matching("origin", f"{FIX_BRANCH}*", repo=repo)))
    for b in local:
        # Fail loud: a local `git branch -D` can be REFUSED (the branch is checked out — in the
        # working tree or a leftover fix worktree), and swallowing that used to report success.
        (did if gitutil.delete_branch(repo, b) else failed).append(f"local {b}")
    for b in remote:
        (did if gitutil.delete_remote_branch("origin", b, repo=repo) else failed).append(f"remote {b}")
    if failed:
        done = f"; deleted {', '.join(did)}" if did else ""
        return (f"{slug}: FAILED to delete {', '.join(failed)} — is it checked out?{done}")
    if did:
        note = " (PR auto-closed)" if any(d.startswith("remote") for d in did) else ""
        return f"{slug}: discarded {', '.join(did)}{note}"
    return f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard"


def discard_pr(repo: Path, token: str) -> str:
    """Close the open `security/auto-clean` PR on the repo's origin (API), leaving the branch."""
    slug = gitutil.origin_slug(repo)
    if not slug:
        return f"{str(repo).replace(str(Path.home()), '~')}: no GitHub origin — no PR to discard"
    return discard_remote_pr(slug, token)


def discard_remote_branch(slug: str, token: str) -> str:
    """Delete FIX_BRANCH on a remote repo by slug, with no local clone — `git push --delete`
    straight to the authed URL (git TLS, SSL-immune). Auto-closes any PR from the branch."""
    with gitutil.github_https_auth(token) as (prefix, env):
        url = f"{prefix}{slug}.git"
        if not gitutil.remote_has_branch(url, FIX_BRANCH, env=env):
            return f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard"
        ok = gitutil.delete_remote_branch(url, FIX_BRANCH, env=env)
    return f"{slug}: deleted {FIX_BRANCH} (PR auto-closed)" if ok else f"{slug}: remote delete failed"


def discard_remote_pr(slug: str, token: str) -> str:
    """Close the open FIX_BRANCH PR(s) on a remote repo by slug (API)."""
    owner, name = slug.split("/", 1)
    existing = github_api.list_open_pulls(owner, name, FIX_BRANCH, token)
    if not existing:
        return f"{slug}: no open '{FIX_BRANCH}' PR"
    closed = [f"#{p['number']}" for p in existing
              if github_api.close_pull(owner, name, p["number"], token)]
    return (f"{slug}: closed PR {', '.join(closed)}" if closed
            else f"{slug}: failed to close PR (network/SSL or token scope)")
