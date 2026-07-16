#!/usr/bin/env python3
"""Push the fix branch — the shareable primitive for publishing a local branch to a GitHub
repo with a token (credential-safe), and for deleting a remote branch."""
from __future__ import annotations

from pathlib import Path

from stayawake.core.git.auth import github_https_auth
from stayawake.core.git.run import run_ok, NETWORK_TIMEOUT


def push_branch(repo: str | Path, slug: str, branch: str, token: str | None,
                *, force: bool = True) -> bool:
    """Push local `branch` to `github.com/<slug>` as `branch`, with the token kept OUT of argv
    and the URL (via GIT_ASKPASS). Returns True on success, False on any failure (no write
    access, network/TLS) so the caller can fall back. The one place `saw fix` and the fork
    fallback both push through — de-duplicated so auth handling can never drift between them."""
    with github_https_auth(token) as (prefix, env):
        args = ["push"]
        if force:
            args.append("--force")
        args += [f"{prefix}{slug}.git", f"{branch}:{branch}"]
        return run_ok(repo, args, env=env, timeout=NETWORK_TIMEOUT)


def delete_remote_branch(remote: str, branch: str, *, repo: str | Path | None = None,
                         env: dict | None = None) -> bool:
    """Delete `branch` on `remote` (`git push <remote> --delete`). Deleting the head branch
    auto-closes any PR opened from it. `remote` is a remote name ('origin', with `repo` set to
    use that clone's own auth) or an explicit URL (with `repo=None` and `env` carrying
    credential-safe auth for a by-slug discard with no local clone)."""
    return run_ok(repo, ["push", remote, "--delete", branch], env=env, timeout=NETWORK_TIMEOUT)
