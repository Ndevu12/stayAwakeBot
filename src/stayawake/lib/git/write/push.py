#!/usr/bin/env python3
"""Push the fix branch to a GitHub repository with a token (credential-safe), and delete a remote
branch. Every push runs from a saw-owned repository, the fix checkout or one borrowing the
operator's objects, sends the branch by commit id, and goes to a checked URL."""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import owned, remote as gitremote
from stayawake.lib.git.auth import run_remote_git
from stayawake.lib.git.borrowed import borrow
from stayawake.lib.git.run import NETWORK_TIMEOUT, OPERATOR_PUSH, SAW_OWNED, run, run_ok
from stayawake.lib.git.write.transfer import resolved
from stayawake.lib.git.write.worktree import held_checkout
from stayawake.utils import scratch


@dataclass(frozen=True)
class PushResult:
    """Outcome of `push_branch_result`. `ok` True on success; else `stderr` for classification."""
    ok: bool
    stderr: str = ""


@contextlib.contextmanager
def _pushing_from(repo: str | Path, branch: str):
    """Yield `(saw_repo, commit)`: a saw-owned repository holding `branch`'s commit, and that
    commit's id. `commit` is "" when `repo` has no such branch."""
    checkout = held_checkout(repo)
    if checkout is not None:
        yield checkout.gitdir, resolved(checkout.gitdir, f"refs/heads/{branch}", context=SAW_OWNED)
        return
    commit = resolved(repo, f"refs/heads/{branch}")
    if not commit:
        yield None, ""
        return
    with borrow(repo) as borrowed:
        yield borrowed.path, commit


def _push(repo: str | Path, slug: str, branch: str, token: str | None,
          refspec_for, extra: tuple[str, ...] = ()) -> PushResult:
    try:
        with _pushing_from(repo, branch) as (source, commit):
            if not commit:
                return PushResult(False, f"no local branch '{branch}' to push")
            res = run_remote_git(slug, token, lambda url, env: (
                run(source, ["push", *extra, url, refspec_for(commit)], env=env,
                    timeout=NETWORK_TIMEOUT, context=OPERATOR_PUSH)
                if gitremote.checked_url(url) else None))
    except OSError as exc:
        return PushResult(False, f"git push could not run: {exc}")
    if res is None:
        return PushResult(False, "git push could not run")
    if res.returncode == 0:
        return PushResult(True, "")
    return PushResult(False, (res.stderr or res.stdout or "").strip())


def push_branch_result(repo: str | Path, slug: str, branch: str, token: str | None) -> PushResult:
    """Push local `branch` to `github.com/<slug>`; return ok + stderr so AuthZ can classify
    workflow-scope / signed-commit / forbidden failures instead of collapsing to 'no write'.

    Does not overwrite a remote ref. A branch that is not fast-forwardable is a refused
    push, not a force-update.
    """
    return _push(repo, slug, branch, token, lambda sha: f"{sha}:refs/heads/{branch}")


def force_update_head(repo: str | Path, slug: str, branch: str, token: str | None,
                      *, lease: str) -> PushResult:
    """Force-update `refs/heads/<branch>` only when `lease` is the SHA it must still be at.

    No lease is not a force-update. The PR path does not call this. The dest is always a
    heads ref so a same-named tag is not updated.
    """
    if not (lease or "").strip():
        return PushResult(False, "remote branch could not be read")
    return _push(repo, slug, branch, token, lambda sha: f"{sha}:refs/heads/{branch}",
                 (f"--force-with-lease=refs/heads/{branch}:{lease}",))


def publish_head(repo: str | Path, slug: str, branch: str, token: str | None,
                 *, dest: str | None = None) -> PushResult:
    """Create `refs/heads/<dest>` on the remote from local `branch`. Does not overwrite an
    existing ref, so publishing beside a protected branch can destroy nothing."""
    target = dest or branch
    return _push(repo, slug, branch, token, lambda sha: f"{sha}:refs/heads/{target}")


def push_branch(repo: str | Path, slug: str, branch: str, token: str | None) -> bool:
    """Push local `branch` to `github.com/<slug>` as `branch`, with the token kept OUT of argv
    and the URL (via GIT_ASKPASS). Returns True on success, False on any failure (no write
    access, network/TLS) so the caller can fall back. Prefer `push_branch_result` when the
    caller must classify the failure (workflow scope vs write access)."""
    return push_branch_result(repo, slug, branch, token).ok


def delete_remote_branch(remote: str, branch: str, *, repo: str | Path | None = None,
                         env: dict | None = None) -> bool:
    """Delete `branch` on `remote` (`git push <url> --delete`). Deleting the head branch
    auto-closes any PR opened from it. `remote` is a remote name ('origin', with `repo` set: its
    URL is read from that clone) or an explicit URL (with `repo=None` and `env` carrying
    credential-safe auth for a by-slug discard with no local clone)."""
    url = gitremote.resolve(remote, repo, for_push=True)
    if url is None:
        return False
    where = scratch.new_dir("an empty repository to push from")
    try:
        if not run_ok(None, ["init", "-q", "--bare", "--template=", str(where)],
                      context=SAW_OWNED):
            return False
        owned.own(where)
        res = run(where, ["push", url, "--delete", f"refs/heads/{branch}"], env=env,
                  timeout=NETWORK_TIMEOUT, context=OPERATOR_PUSH)
    finally:
        owned.disown(where)
        scratch.release_path(where)
    return res is not None and res.returncode == 0
