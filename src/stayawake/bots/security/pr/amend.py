#!/usr/bin/env python3
"""`saw fix amend` — replace past commits that still carry the payload and force-update
each branch they sat on. Never `--pr`. Never moves a tag.

Bare `saw fix` is unchanged. A local rewrite that does not update the remote is not a fix.
"""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.lib.git.auth import github_https_auth
from stayawake.lib.git.run import NETWORK_TIMEOUT, run
from stayawake.bots.security.pr.amend_outcome import (AmendOutcome, BranchResult, Cause, Reason,
                                                      amended, refused, render_amend_line)
from stayawake.lib.git import authority
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write.capture import capture_bundle
from stayawake.lib.git.write.push import PushResult, force_update_head, publish_head
from stayawake.lib.git.write.sign import signing_status
from stayawake.lib import git as gitutil


def _full(repo: Path, sha: str) -> str:
    return gitutil.stdout(repo, ["rev-parse", "--verify", f"{sha}^{{commit}}"]).strip()


def _confirmed_commits(scan) -> list:
    found = []
    seen: set[str] = set()
    for f in scan.findings:
        if getattr(f, "vector", None) != "evil-merge":
            continue
        if getattr(f, "confidence", None) != CONFIRMED:
            continue
        sha = getattr(f, "commit_sha", None)
        if not sha or sha in seen:
            continue
        seen.add(sha)
        found.append(f)
    return found


_OID = set("0123456789abcdef")


def _is_oid(s: str) -> bool:
    s = (s or "").strip().lower()
    return len(s) == 40 and all(c in _OID for c in s)


def _read_remote_head(repo: Path, slug: str, branch: str,
                      token: str | None) -> tuple[bool, str | None]:
    """`(known, sha)`. `known` False means the lookup did not finish. `sha` None when
    `known` is True means the heads ref is absent."""
    with github_https_auth(token) as (prefix, env):
        res = run(repo, ["ls-remote", "--heads", f"{prefix}{slug}.git", f"refs/heads/{branch}"],
                  env=env, timeout=NETWORK_TIMEOUT)
    if res is None or res.returncode != 0:
        return False, None
    lines = [ln for ln in (res.stdout or "").splitlines() if ln.strip()]
    if not lines:
        return True, None
    sha = lines[0].split()[0]
    if not _is_oid(sha):
        return False, None
    return True, sha


def _collect_remote_heads(repo: Path, slug: str, names: list[str],
                          token: str | None) -> tuple[dict[str, str | None] | None, str | None]:
    """Each branch's remote SHA (`None` if absent). `(None, name)` when `name` could not be read."""
    found: dict[str, str | None] = {}
    for name in names:
        known, sha = _read_remote_head(repo, slug, name, token)
        if not known:
            return None, name
        found[name] = sha
    return found, None


def _destination(slug: str, branch: str, token: str | None,
                 sha12: str) -> tuple[str, Reason | None]:
    """Where this branch's amended history goes.

    A protected branch — or one whose rule could not be read — is never force-updated: the
    maintainer drew that boundary and an unreadable rule is not permission. The amended history is
    published beside it under its own name, which overwrites nothing, and a person opens the PR.
    """
    protection = authority.ref_protection(slug, branch, token)
    if protection.protected is False:
        return branch, None
    cause = Cause.BRANCH_PROTECTED if protection.protected else Cause.PROTECTION_UNKNOWN
    aside = f"security/amend-{sha12}"
    return aside, Reason(cause, aside)


def _push_to(repo: Path, slug: str, branch: str, dest: str, token: str | None,
             lease: str | None, pusher) -> PushResult:
    """The transport, and the only part a caller may substitute. Force-updating needs a lease and
    a destination equal to the source; everything else creates a ref and overwrites nothing."""
    if pusher is not None:
        return pusher(branch, dest, lease)
    if dest != branch or lease is None:
        return publish_head(repo, slug, branch, token, dest=dest)
    return force_update_head(repo, slug, branch, token, lease=lease)


def _force_update_branch(repo: Path, slug: str, branch: str, token: str | None, *,
                         pusher, lease: str | None = None,
                         sha12: str = "") -> BranchResult:
    dest, aside = _destination(slug, branch, token, sha12)
    result = _push_to(repo, slug, branch, dest, token, lease, pusher)
    if aside is not None:
        return BranchResult(branch, False,
                            aside if result.ok else Reason(Cause.PUSH_REFUSED, branch))
    if result.ok and pusher is None:
        known, remote = _read_remote_head(repo, slug, branch, token)
        local = gitutil.stdout(repo, ["rev-parse", f"refs/heads/{branch}"]).strip()
        if not known or not remote or not local or remote != local:
            result = PushResult(False)
    if not result.ok:
        return BranchResult(branch, False, Reason(Cause.PUSH_REFUSED, branch))
    return BranchResult(branch, True)


def _capture_path(repo: Path, sha12: str) -> Path:
    """Where the objects the replacement orphans are captured before any ref moves.

    Inside the git directory, never the worktree: a new file in the worktree makes the tree
    dirty, and a dirty tree is precisely what `point_branch_at` refuses to move a branch over —
    so capturing there would abort the very amend it exists to make safe.
    """
    git_dir = gitutil.stdout(repo, ["rev-parse", "--absolute-git-dir"]).strip()
    root = Path(git_dir) if git_dir else Path(repo) / ".git"
    return root / "saw-amend" / sha12 / "capture.bundle"


def _reconstruction_cause(repo: Path, sha: str) -> Cause:
    """Why no replacement exists. "This shape is not modelled" and "the merge would not resolve"
    are different answers and the operator acts differently on each."""
    if len(gitutil.parents(repo, sha)) != 2:
        return Cause.COMMIT_SHAPE_NOT_MODELLED
    return Cause.MERGE_WOULD_NOT_RESOLVE


def _survivors(repo: Path, old: str) -> list[Reason]:
    """What the force-update leaves reachable. Each one makes the run need review.

    Forks are never established: nothing an origin owner does removes an object from a fork, and
    this path does not enumerate them — so the run says it did not look rather than that there
    are none."""
    reasons = [Reason(Cause.PREVIOUS_OBJECTS_UNCOLLECTED)]
    tags = gitutil.stdout(repo, ["tag", "--points-at", old]).split()
    if tags:
        reasons.append(Reason(Cause.TAGS_AT_REPLACED_COMMIT, ", ".join(sorted(tags))))
    reasons.append(Reason(Cause.FORKS_NOT_ESTABLISHED))
    return reasons


def amend_repo(repo: Path, opts, signatures, allowlist, token: str | None = None, *,
               pusher=None) -> str:
    """Force-update every branch that still reaches a confirmed past-commit payload.

    The local rewrite is a step. The result is the remote refs moving. Returns one operator line.
    """
    display = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    outcome = amend_outcome(repo, display, opts, signatures, allowlist, token, pusher=pusher)
    return render_amend_line(outcome)


def amend_outcome(repo: Path, display: str, opts, signatures, allowlist, token, *,
                  pusher=None) -> AmendOutcome:
    """The act, as a structure. Prose is rendered from this and never parsed back out of it."""
    if not gitutil.is_git_repo(repo):
        return refused(display, Cause.NOT_A_GIT_REPOSITORY)
    if gitamend.is_dirty(repo):
        return refused(display, Cause.WORKING_TREE_NOT_CLEAN)

    slug = gitutil.origin_slug(repo)
    if not slug:
        return refused(display, Cause.NO_REMOTE)
    if not (token or "").strip() and pusher is None:
        return refused(display, Cause.NO_CREDENTIAL)

    permitted = authority.may_rewrite(slug, token)
    if not permitted.permitted:
        return refused(display, Cause.NOT_PERMITTED_TO_REWRITE, permitted.reason)
    fetched = gitutil.fetch_refs(repo, token=token)
    if not fetched.ok:
        return refused(display, Cause.REMOTE_REFS_UNREADABLE, fetched.reason)

    signing = signing_status(repo)
    if signing.must_refuse:
        return refused(display, Cause.SIGNING_UNAVAILABLE, signing.reason)

    scan = scan_target(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)
    if scan.error is not None:
        return refused(display, Cause.SCAN_DID_NOT_FINISH)
    commits = _confirmed_commits(scan)
    if not commits:
        return refused(display, Cause.NO_CONFIRMED_PAYLOAD)
    if len(commits) > 1:
        shas = ", ".join((_full(repo, getattr(f, "commit_sha", None) or "") or f.path)[:12]
                         for f in commits)
        return refused(display, Cause.MANY_CONFIRMED_COMMITS, str(len(commits)), shas)

    finding = commits[0]
    old = _full(repo, finding.commit_sha or "")
    if not old:
        return refused(display, Cause.CONFIRMED_COMMIT_UNRESOLVED)
    heads = gitamend.carrying_branches(repo, old)
    if not heads:
        return refused(display, Cause.COMMIT_ON_NO_BRANCH, old[:12])

    leases, unread = _collect_remote_heads(repo, slug, [n for n, _, _ in heads], token)
    if unread is not None:
        return refused(display, Cause.REMOTE_BRANCH_UNREADABLE, unread)

    new = gitamend.reconstruct_merge(repo, old, signing)
    if new is None:
        return refused(display, _reconstruction_cause(repo, old), old[:12])

    signature_paths = tuple(getattr(finding, "related_paths", ()) or ())
    lost = gitamend.discarded_delta(repo, old, new)
    unexplained = [p for p in lost if p not in signature_paths]
    if unexplained:
        return refused(display, Cause.REPLACEMENT_LOSES_MORE_THAN_THE_PAYLOAD,
                       ", ".join(sorted(unexplained)[:5]))

    captured = capture_bundle(repo, [(tip, new) for _n, tip, _c in heads],
                              _capture_path(repo, old[:12]))
    if not captured.ok:
        return refused(display, Cause.CAPTURE_FAILED, captured.reason)

    try:
        moved = gitamend.apply_replacement(repo, old, new, heads, signing)
    except gitamend.AmendUnwindFailed as unwound:
        return refused(display, Cause.LEFT_PART_WAY, ", ".join(unwound.unrestored))
    if moved is None:
        return refused(display, Cause.REPLAY_FAILED, ", ".join(n for n, _, _ in heads))

    faithful, drift = gitamend.replay_is_faithful(repo, heads[0][1], moved[heads[0][0]], old, new,
                                                 signature_paths)
    if not faithful:
        unrestored = gitamend.restore_branches(repo, heads, moved, list(moved))
        if unrestored:
            return refused(display, Cause.LEFT_PART_WAY, ", ".join(unrestored))
        return refused(display, Cause.REPLAY_CHANGED_UNRELATED_COMMITS, "; ".join(drift[:3]))

    results: list[BranchResult] = []
    failed: list[str] = []
    for branch in moved:
        result = _force_update_branch(repo, slug, branch, token, pusher=pusher,
                                      lease=(leases or {}).get(branch), sha12=old[:12])
        results.append(result)
        if not result.force_updated:
            failed.append(branch)
    if failed:
        gitamend.restore_branches(repo, heads, moved, failed)
    return amended(display, old[:12], tuple(results), tuple(_survivors(repo, old)))
