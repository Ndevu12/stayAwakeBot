#!/usr/bin/env python3
"""`saw discard` — the inverse of fix: delete the auto-clean branch / close its PR, locally or on a remote."""
from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess

from stayawake.lib.adapters import github_api
from stayawake.lib import git as gitutil
from stayawake.bots.security.pr.constants import FIX_BRANCH


def _fix_branches_on(remote: str, *, repo: str | Path | None = None,
                     env: dict | None = None) -> list[str] | None:
    """Every auto-clean branch on `remote`, including the plain name an older run left.
    `None` when the remote could not be listed."""
    found = gitutil.remote_branches_matching(remote, f"{FIX_BRANCH}*", repo=repo, env=env)
    return None if found is None else sorted(set(found))


def _outcome(slug: str, did: list[str], failed: list[str]) -> str:
    if failed:
        done = f"; deleted {', '.join(did)}" if did else ""
        return f"{slug}: FAILED to delete {', '.join(failed)}{done}"
    if did:
        note = " (PR auto-closed)" if any(d.startswith("remote") for d in did) else ""
        return f"{slug}: discarded {', '.join(did)}{note}"
    return f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard"


def discard_branch(repo: Path) -> str:
    """Delete the local `security/auto-clean` branch and origin's copy, using the repo's own
    `origin` auth (SSH key / credential helper) — no GitHub API, so it works even when the
    API is unreachable. Deleting the remote branch auto-closes any PR opened from it."""
    slug = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    did: list[str] = []
    failed: list[str] = []
    local = sorted(set(gitutil.branches_matching(repo, f"{FIX_BRANCH}*"))
                   | ({FIX_BRANCH} if gitutil.ref_exists(repo, f"refs/heads/{FIX_BRANCH}") else set()))
    remote = _fix_branches_on("origin", repo=repo)
    for b in local:
        (did if gitutil.delete_branch(repo, b) else failed).append(f"local {b}")
    if remote is None:
        if gitutil.stdout(repo, ["remote", "get-url", "origin"]).strip():
            failed.append("remote branches")
    else:
        for b in remote:
            (did if gitutil.delete_remote_branch("origin", b, repo=repo) else failed).append(f"remote {b}")
    if failed and any(f.startswith("local ") for f in failed):
        done = f"; deleted {', '.join(did)}" if did else ""
        return (f"{slug}: FAILED to delete {', '.join(failed)} — is it checked out?{done}")
    return _outcome(slug, did, failed)


def discard_pr(repo: Path, token: str) -> str:
    """Close the open `security/auto-clean` PR on the repo's origin (API), leaving the branch."""
    slug = gitutil.origin_slug(repo)
    if not slug:
        return f"{str(repo).replace(str(Path.home()), '~')}: no GitHub origin — no PR to discard"
    return discard_remote_pr(slug, token)


def _listed_on_github(slug: str, token: str) -> list[str] | None:
    """Auto-clean branches on `github.com/<slug>`."""
    found: list[str] | None = None

    def attempt(url, env):
        nonlocal found
        names = _fix_branches_on(url, env=env)
        if names is None:
            return CompletedProcess(args=[], returncode=1)
        found = names
        return CompletedProcess(args=[], returncode=0)

    gitutil.run_remote_git(slug, token, attempt)
    return found


def discard_remote_branch(slug: str, token: str) -> str:
    """Delete every auto-clean branch on a remote repo by slug, with no local clone.
    Auto-closes any PR opened from a branch it deletes."""
    listed = _listed_on_github(slug, token)
    if listed is None:
        return f"{slug}: FAILED to list remote branches"
    if not listed:
        return f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard"
    did: list[str] = []
    failed: list[str] = []
    with gitutil.github_remote(slug, token) as (url, env):
        for b in listed:
            (did if gitutil.delete_remote_branch(url, b, env=env) else failed).append(f"remote {b}")
    return _outcome(slug, did, failed)


def discard_remote_pr(slug: str, token: str) -> str:
    """Close the open auto-clean PR(s) on a remote repo by slug (API)."""
    owner, name = slug.split("/", 1)
    heads = _listed_on_github(slug, token)
    if heads is None:
        return f"{slug}: FAILED to list remote branches"
    if not heads:
        return f"{slug}: no open '{FIX_BRANCH}' PR"
    closed: list[str] = []
    saw_open = False
    for head in heads:
        existing = github_api.list_open_pulls(owner, name, head, token)
        if existing:
            saw_open = True
        closed.extend(f"#{p['number']}" for p in existing
                      if github_api.close_pull(owner, name, p["number"], token))
    if closed:
        return f"{slug}: closed PR {', '.join(closed)}"
    if saw_open:
        return f"{slug}: failed to close PR (network/SSL or token scope)"
    return f"{slug}: no open '{FIX_BRANCH}' PR"
