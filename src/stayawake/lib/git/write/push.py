#!/usr/bin/env python3
"""Push the fix branch — the shareable primitive for publishing a local branch to a GitHub
repo with a token (credential-safe), and for deleting a remote branch."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.auth import github_https_auth
from stayawake.lib.git.run import run, run_ok, NETWORK_TIMEOUT


@dataclass(frozen=True)
class PushResult:
    """Outcome of `push_branch_result`. `ok` True on success; else `stderr` for classification."""
    ok: bool
    stderr: str = ""


def push_branch_result(repo: str | Path, slug: str, branch: str, token: str | None) -> PushResult:
    """Push local `branch` to `github.com/<slug>`; return ok + stderr so AuthZ can classify
    workflow-scope / signed-commit / forbidden failures instead of collapsing to 'no write'.

    Does not overwrite a remote ref. A branch that is not fast-forwardable is a refused
    push, not a force-update.
    """
    with github_https_auth(token) as (prefix, env):
        args = ["push", f"{prefix}{slug}.git", f"{branch}:{branch}"]
        res = run(repo, args, env=env, timeout=NETWORK_TIMEOUT)
    if res is None:
        return PushResult(False, "git push could not run")
    if res.returncode == 0:
        return PushResult(True, "")
    return PushResult(False, (res.stderr or res.stdout or "").strip())


def force_update_head(repo: str | Path, slug: str, branch: str, token: str | None,
                      *, lease: str | None = None) -> PushResult:
    """Force-update `refs/heads/<branch>` only. The PR path does not call this.

    `lease` is the SHA the remote heads ref must still be at. The dest is always a heads
    ref so a same-named tag is not updated.
    """
    with github_https_auth(token) as (prefix, env):
        args = ["push"]
        if lease:
            args.append(f"--force-with-lease=refs/heads/{branch}:{lease}")
        else:
            args.append("--force")
        args += [f"{prefix}{slug}.git", f"{branch}:refs/heads/{branch}"]
        res = run(repo, args, env=env, timeout=NETWORK_TIMEOUT)
    if res is None:
        return PushResult(False, "git push could not run")
    if res.returncode == 0:
        return PushResult(True, "")
    return PushResult(False, (res.stderr or res.stdout or "").strip())


def push_branch(repo: str | Path, slug: str, branch: str, token: str | None) -> bool:
    """Push local `branch` to `github.com/<slug>` as `branch`, with the token kept OUT of argv
    and the URL (via GIT_ASKPASS). Returns True on success, False on any failure (no write
    access, network/TLS) so the caller can fall back. Prefer `push_branch_result` when the
    caller must classify the failure (workflow scope vs write access)."""
    return push_branch_result(repo, slug, branch, token).ok


def delete_remote_branch(remote: str, branch: str, *, repo: str | Path | None = None,
                         env: dict | None = None) -> bool:
    """Delete `branch` on `remote` (`git push <remote> --delete`). Deleting the head branch
    auto-closes any PR opened from it. `remote` is a remote name ('origin', with `repo` set to
    use that clone's own auth) or an explicit URL (with `repo=None` and `env` carrying
    credential-safe auth for a by-slug discard with no local clone)."""
    return run_ok(repo, ["push", remote, "--delete", branch], env=env, timeout=NETWORK_TIMEOUT)
