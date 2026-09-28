#!/usr/bin/env python3
"""Refresh the operator's remote-tracking refs without running `git fetch` in their repository. The
fetch runs in a saw-owned repository that borrows their objects and carries a copy of their refs;
what changed is handed back as data, the new objects as a pack (`transfer.adopt_objects`) and the
refs in one compare-and-swap `update-ref` transaction."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git import remote as gitremote
from stayawake.lib.git.auth import github_https_auth, run_remote_git
from stayawake.lib.git.borrowed import borrow
from stayawake.lib.git.query import FetchResult, origin_slug
from stayawake.lib.git.run import NETWORK_TIMEOUT, OPERATOR_PUSH, SAW_OWNED, run
from stayawake.lib.git.write.branch import refs_under, update_refs
from stayawake.lib.git.write.transfer import adopt_objects

_MIRRORED_REFS = ("refs/heads", "refs/remotes", "refs/tags")


def _without_token(text: str, token: str | None) -> str:
    return text.replace(token, "***") if token else text


def _fetch_through(repo: str | Path, fetch_args: list[str], attempt) -> FetchResult:
    """Fetch into a borrowed copy of `repo`, then carry every changed ref outside `refs/heads`
    back. `attempt(run_fetch)` chooses the URL and credentials and returns what `run_fetch(url,
    env)` returned."""
    before = refs_under(repo, *_MIRRORED_REFS)
    try:
        with borrow(repo) as borrowed:
            if not update_refs(borrowed.path, [(r, o, "") for r, o in before.items()],
                               context=SAW_OWNED):
                return FetchResult(False, "the repository's refs could not be copied to fetch with")
            res = attempt(lambda url, env: run(
                borrowed.path, ["fetch", "--quiet", *fetch_args[:-1], url, fetch_args[-1]],
                env=env, timeout=NETWORK_TIMEOUT, context=OPERATOR_PUSH)
                if gitremote.checked_url(url) else None)
            if res is None:
                return FetchResult(False, "git fetch could not run, was refused the remote's "
                                          "address, or exceeded the network timeout")
            if res.returncode != 0:
                return FetchResult(False, (res.stderr or res.stdout or "").strip()
                                   or f"git fetch exited {res.returncode}")
            after = refs_under(borrowed.path, *_MIRRORED_REFS, context=SAW_OWNED)
            changes = [(ref, after.get(ref, ""), before.get(ref, ""))
                       for ref in sorted(set(before) | set(after))
                       if not ref.startswith("refs/heads/") and after.get(ref) != before.get(ref)]
            tips = sorted({new for _ref, new, _old in changes if new})
            if tips:
                failure = adopt_objects(repo, borrowed.path, tips, sorted(set(before.values())))
                if failure:
                    return FetchResult(False, failure)
    except OSError as exc:
        return FetchResult(False, str(exc))
    if not update_refs(repo, changes):
        return FetchResult(False, "the remote-tracking refs changed while they were fetched")
    return FetchResult(True)


def fetch(repo: str | Path, remote: str, ref: str) -> bool:
    """Refresh `refs/remotes/<remote>/<ref>` from `remote`'s address in `repo`. Best-effort: the
    caller falls back to the local base when this fails (offline), and the network timeout bounds
    a hung fetch."""
    url = gitremote.remote_url(repo, remote)
    if url is None:
        return False
    refspec = f"+refs/heads/{ref}:refs/remotes/{remote}/{ref}"
    with github_https_auth(None) as (_prefix, env):
        return _fetch_through(repo, [refspec], lambda go: go(url, env)).ok


def fetch_refs(repo: str | Path, *, token: str | None = None) -> FetchResult:
    """Refresh every `refs/remotes/origin/*` from the remote, pruning the ones it no longer has.

    `branches_carrying` can only see branches this clone fetched, so on a stale clone a branch
    that carries an infected commit is invisible and a sweep reports it updated every carrier
    when it did not. The explicit `+refs/heads/*:refs/remotes/origin/*` is what makes the
    refresh complete: the clone's CONFIGURED refspec may be narrowed to one branch by a
    `--single-branch` clone. `--prune` is the other half — a branch deleted on the remote must
    stop counting as a carrier.

    Never raises, and never reports success it did not achieve: git failing, being unable to
    run, or exceeding `NETWORK_TIMEOUT` all return `ok=False` with a reason. `token`
    authenticates through `github_https_auth`, so the secret reaches git only in the child
    environment; git's own message is scrubbed of it before it becomes a `reason`.
    """
    slug = origin_slug(repo) if token else None
    args = ["--prune", "--no-tags", "+refs/heads/*:refs/remotes/origin/*"]
    if slug:
        result = _fetch_through(repo, args, lambda go: run_remote_git(slug, token, go))
    else:
        url = gitremote.remote_url(repo, "origin")
        if url is None:
            return FetchResult(False, "origin has no address git may fetch from")
        with github_https_auth(token) as (_prefix, env):
            result = _fetch_through(repo, args, lambda go: go(url, env))
    return result if result.ok else FetchResult(False, _without_token(result.reason, token))
