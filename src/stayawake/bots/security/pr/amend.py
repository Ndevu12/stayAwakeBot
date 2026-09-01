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
from stayawake.bots.security.pr.outcome import (AmendOutcome, BranchResult, Cause, Reason,
                                                      amended, refused, render_amend_line)
from stayawake.lib.git import authority
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write import rebuild as gitrebuild
from stayawake.lib.git.write.capture import capture_bundle
from stayawake.lib.git.write.push import PushResult, force_update_head, publish_head
from stayawake.lib.git.write import sign
from stayawake.lib import git as gitutil
from stayawake.utils import env


def _full(repo: Path, sha: str) -> str:
    return gitutil.stdout(repo, ["rev-parse", "--verify", f"{sha}^{{commit}}"]).strip()


def _payload_left(repo: Path, infected, rebuilt, new_tips: dict[str, str],
                  still_carries) -> list[str]:
    """What the rebuild produced that still reaches the payload. Empty means it did its job.

    Every other check in this path asks what CHANGED. None of them asks whether anything infected
    REMAINS, and those are different questions — a correction that quietly did nothing changes
    nothing and passes them all.

    Asked of the rebuilt objects, before any reference moves, so a failure needs nothing put back.
    Re-scanning the repository instead would be answered by the OLD commits, which are still
    reachable through the remote-tracking refs this run has not pushed over yet.
    """
    left = []
    for old in sorted(infected):
        for tip in sorted(set(new_tips.values())):
            if gitutil.is_ancestor(repo, old, tip):
                left.append(f"{old[:12]} is still reachable from the rebuilt history")
    if not still_carries:
        return left
    paths = {p for group in infected.values() for p in group}
    for sha in sorted(set(rebuilt.mapping.values())):
        for path in sorted(paths):
            carried = still_carries(gitutil.file_at(repo, sha, path))
            if carried:
                left.append(f"{sha[:12]} still carries {path} ({carried})")
    return left


def _branches_carrying_any(repo: Path, infected) -> list[tuple[str, str, str]]:
    """Every branch that reaches ANY of the infected commits, each named once.

    A branch is rebuilt from the oldest payload it carries, so a branch reaching two of them is
    still one branch to move.
    """
    heads: dict[str, tuple[str, str, str]] = {}
    for sha in infected:
        for name, tip, cas_old in gitutil.branches_carrying(repo, sha):
            heads.setdefault(name, (name, tip, cas_old))
    return list(heads.values())


def _confirmed_commits(scan) -> list:
    """Confirmed findings that name a commit and the paths in it to correct.

    The shape of the commit no longer decides this — an ordinary commit that introduced the
    payload is as replaceable as a merge that smuggled it, and the reconstruction picks the clean
    content from the commit's own shape.
    """
    found = []
    seen: set[str] = set()
    for f in scan.findings:
        if getattr(f, "confidence", None) != CONFIRMED:
            continue
        if not getattr(f, "related_paths", None):
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
    # `ls-remote <pattern>` tail-matches at `/`, so a ref named `a/refs/heads/main` answers a query
    # for `main` and sorts first — anyone who can push could choose the SHA this returns.
    wanted = f"refs/heads/{branch}"
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1].strip() != wanted:
            continue
        sha = parts[0].strip()
        return (True, sha) if _is_oid(sha) else (False, None)
    return True, None


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
             lease: str | None, pusher, *, force: bool) -> PushResult:
    """The transport, and the only part a caller may substitute.

    `force` is passed in rather than re-derived from `dest != branch`: a branch named exactly like
    the aside ref makes those two names equal, and the transport would then force-update the very
    ref the destination decision had just protected.
    """
    if pusher is not None:
        return pusher(branch, dest, lease)
    if not force or lease is None:
        return publish_head(repo, slug, branch, token, dest=dest)
    return force_update_head(repo, slug, branch, token, lease=lease)


def _force_update_branch(repo: Path, slug: str, branch: str, token: str | None, *,
                         pusher, lease: str | None = None,
                         sha12: str = "") -> BranchResult:
    dest, aside = _destination(slug, branch, token, sha12)
    result = _push_to(repo, slug, branch, dest, token, lease, pusher,
                      force=aside is None)
    if aside is not None:
        return BranchResult(branch, False,
                            aside if result.ok else Reason(Cause.PUSH_REFUSED, branch))
    if not result.ok:
        return BranchResult(branch, False, Reason(Cause.PUSH_REFUSED, branch))
    if pusher is not None:
        return BranchResult(branch, True)
    known, remote = _read_remote_head(repo, slug, branch, token)
    local = gitutil.stdout(repo, ["rev-parse", f"refs/heads/{branch}"]).strip()
    if known and remote and local and remote == local:
        return BranchResult(branch, True)
    if not known:
        # An accepted push whose result cannot be read back is not a refusal. Calling it one used
        # to send the local branch back to the payload tip, which GUARANTEES the divergence the
        # restore was meant to avoid: the remote most likely holds the replacement.
        return BranchResult(branch, False, Reason(Cause.PUSH_NOT_CONFIRMED, branch))
    return BranchResult(branch, False, Reason(Cause.REMOTE_DID_NOT_MOVE, branch))


def _capture_path(slug: str, sha12: str) -> Path:
    """Where the objects the replacement orphans are captured before any ref moves.

    Outside the repository entirely. Inside the worktree a new file makes the tree dirty and the
    ref move is then refused; inside the git directory the capture dies with the checkout, and on
    `--remote` that checkout is a temporary clone deleted seconds after the remote refs move — so
    the evidence had a shorter life than the destruction it authorised. Cross-run state is the one
    place that outlives both.
    """
    safe = "".join(c if c.isalnum() or c in "-._" else "-" for c in slug) or "repository"
    return Path(env.xdg_state_home()) / "saw" / "amend" / safe / sha12 / "capture.bundle"


_CAUSE_PER_REFUSAL_KIND = {
    "conflicted": Cause.MERGE_WOULD_NOT_RESOLVE,
    "shape": Cause.COMMIT_SHAPE_NOT_MODELLED,
    "submodule": Cause.PAYLOAD_IN_A_SUBMODULE,
    "unnamed": Cause.COMMIT_SHAPE_NOT_MODELLED,
    "not-applied": Cause.REPLACEMENT_DID_NOT_APPLY,
    "headers": Cause.COMMIT_RECORDS_MORE_THAN_A_REPLACEMENT_CARRIES,
    "message-encoding": Cause.COMMIT_RECORDS_MORE_THAN_A_REPLACEMENT_CARRIES,
    "message": Cause.REPLACEMENT_NOT_WRITTEN,
    "baseline-carries-payload": Cause.PAYLOAD_PREDATES_THIS_COMMIT,
    "changed-downstream": Cause.PAYLOAD_CHANGED_AFTER_THIS_COMMIT,
}


def _survives(signatures) -> object:
    """Whether content still looks loader-shaped, for judging what a revert would restore.

    Every tier, not only the confirmed one: this asks whether anything survived an excision, and
    a heuristic match must still block a claim that the payload is gone.
    """
    from stayawake.bots.security.matchers.base import build_any_loader_check
    flat = [s for group in (signatures or {}).values() for s in group] \
        if isinstance(signatures, dict) else list(signatures or [])
    return build_any_loader_check(flat)


def _tags_at(repo: Path, slug: str, olds: list[str], token: str | None) -> tuple[list[str], bool]:
    """Tag names still pointing at the replaced commit, and whether that could be established.

    Asked of the REMOTE, not of this clone. The refresh this run does is `--no-tags`, so a tag
    pushed since the operator last fetched is invisible here — and one `clone --branch <tag>` puts
    the payload back on disk. `ls-remote --tags` reports both the tag object and its peeled `^{}`
    line, so an annotated tag is matched by the commit it resolves to.
    """
    local = [name for sha in olds
             for name in gitutil.stdout(repo, ["tag", "--points-at", sha]).split()]
    with github_https_auth(token) as (prefix, env_):
        res = run(repo, ["ls-remote", "--tags", f"{prefix}{slug}.git"],
                  env=env_, timeout=NETWORK_TIMEOUT)
    if res is None or res.returncode != 0:
        return sorted(set(local)), False
    remote = []
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].strip() in set(olds) and parts[1].startswith("refs/tags/"):
            remote.append(parts[1][len("refs/tags/"):].removesuffix("^{}"))
    return sorted(set(local) | set(remote)), True


def _survivors(repo: Path, slug: str, olds: list[str], token: str | None) -> list[Reason]:
    """What the force-update leaves reachable. Each one makes the run need review.

    Forks are counted rather than assumed. Reporting "forks were not established" on every run
    made `needs_review` True for every outcome the module could produce, refused and completed
    alike — a flag that fires every time carries no information and hides the runs that really do
    need a person.
    """
    reasons = [Reason(Cause.PREVIOUS_OBJECTS_UNCOLLECTED)]
    tags, established = _tags_at(repo, slug, olds, token)
    if tags:
        reasons.append(Reason(Cause.TAGS_AT_REPLACED_COMMIT, ", ".join(sorted(tags))))
    elif not established:
        reasons.append(Reason(Cause.TAGS_NOT_ESTABLISHED))
    forks = authority.fork_count(slug, token)
    if forks is None:
        reasons.append(Reason(Cause.FORKS_NOT_ESTABLISHED))
    elif forks:
        reasons.append(Reason(Cause.FORKS_EXIST, str(forks)))
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

    scan = scan_target(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)
    if scan.error is not None:
        return refused(display, Cause.SCAN_DID_NOT_FINISH)
    commits = _confirmed_commits(scan)
    if not commits:
        return refused(display, Cause.NO_CONFIRMED_PAYLOAD)

    infected: dict[str, tuple[str, ...]] = {}
    for finding in commits:
        sha = _full(repo, getattr(finding, "commit_sha", None) or "")
        if not sha:
            return refused(display, Cause.CONFIRMED_COMMIT_UNRESOLVED)
        paths = tuple(getattr(finding, "related_paths", ()) or ())
        if not paths:
            return refused(display, Cause.COMMIT_SHAPE_NOT_MODELLED, sha[:12])
        infected[sha] = tuple(dict.fromkeys(infected.get(sha, ()) + paths))

    heads = _branches_carrying_any(repo, infected)
    if not heads:
        return refused(display, Cause.COMMIT_ON_NO_BRANCH,
                       ", ".join(sorted(s[:12] for s in infected)))

    graph = gitrebuild.ordered_graph(repo, [tip for _n, tip, _c in heads])
    plan = gitrebuild.commits_to_rebuild(graph, set(infected))
    uncovered = sorted(s for s in infected if s not in {sha for sha, _ps in plan})
    if uncovered:
        # A confirmed commit no branch reaches is not amendable here, and counting it as replaced
        # would report commits the run never touched.
        return refused(display, Cause.COMMIT_ON_NO_BRANCH,
                       ", ".join(s[:12] for s in uncovered))
    oldest = plan[0][0]

    # Asked AFTER the set is known: whether this owes a signature depends on what the commits
    # being rewritten carry, not only on what this clone's config asks for.
    signing = sign.signing_status(
        repo, history_is_signed=sign.any_signed(repo, [sha for sha, _ps in plan]))
    if signing.must_refuse:
        return refused(display, Cause.SIGNING_UNAVAILABLE, signing.reason)
    if sign.committer_identity(repo) is None:
        return refused(display, Cause.NO_COMMITTER_IDENTITY)

    leases, unread = _collect_remote_heads(repo, slug, [n for n, _, _ in heads], token)
    if unread is not None:
        return refused(display, Cause.REMOTE_BRANCH_UNREADABLE, unread)
    behind = sorted(name for name, tip, _cas in heads
                    if leases.get(name) and not gitutil.is_ancestor(repo, leases[name], tip))
    if behind:
        return refused(display, Cause.LOCAL_MISSING_REMOTE_COMMITS, ", ".join(behind))

    survives = _survives(signatures)
    replacements = {}
    for sha, paths in infected.items():
        replacement = gitamend.replacement_commit(repo, sha, paths, signing, survives)
        if not replacement.ok:
            return refused(display,
                           _CAUSE_PER_REFUSAL_KIND.get(replacement.kind,
                                                  Cause.REPLACEMENT_NOT_WRITTEN),
                           replacement.refusal or sha[:12])
        beyond = [p for p in gitamend.discarded_delta(repo, sha, replacement.sha)
                  if p not in paths]
        if beyond:
            return refused(display, Cause.REPLACEMENT_LOSES_MORE_THAN_THE_PAYLOAD,
                           ", ".join(sorted(beyond)[:5]))
        replacements[sha] = replacement

    # Objects only — no reference moves until the capture below has been read back.
    rebuilt = gitrebuild.rebuild_without_payload(
        repo, plan, replacements,
        lambda sha, tree, new_parents: gitamend.rewrite_commit(repo, sha, tree, new_parents,
                                                               signing),
        survives)
    if not rebuilt.ok:
        return refused(display,
                       _CAUSE_PER_REFUSAL_KIND.get(rebuilt.kind, Cause.REPLACEMENT_NOT_WRITTEN),
                       rebuilt.refusal)

    new_tips = {tip: rebuilt.tip(tip) for _n, tip, _c in heads}
    flagged = {p for paths in infected.values() for p in paths}
    for name, tip, _cas in heads:
        beyond = [p for p in gitamend.discarded_delta(repo, tip, new_tips[tip])
                  if p not in flagged]
        if beyond:
            return refused(display, Cause.REPLAY_CHANGED_UNRELATED_COMMITS,
                           f"{name}: " + ", ".join(sorted(beyond)[:3]))

    left = _payload_left(repo, infected, rebuilt, new_tips, survives)
    if left:
        return refused(display, Cause.PAYLOAD_STILL_REACHABLE, "; ".join(left[:3]))

    captured = capture_bundle(repo, [(tip, new_tips[tip]) for _n, tip, _c in heads],
                              _capture_path(slug, oldest[:12]))
    if not captured.ok:
        return refused(display, Cause.CAPTURE_FAILED, captured.reason)

    try:
        moved = gitamend.point_branches(repo, heads, new_tips)
    except gitamend.AmendUnwindFailed as unwound:
        return refused(display, Cause.LEFT_PART_WAY, ", ".join(unwound.unrestored))
    if moved is None:
        return refused(display, Cause.REPLAY_FAILED, ", ".join(n for n, _, _ in heads))

    results: list[BranchResult] = []
    failed: list[str] = []
    for branch in moved:
        result = _force_update_branch(repo, slug, branch, token, pusher=pusher,
                                      lease=(leases or {}).get(branch),
                                      sha12=oldest[:12])
        results.append(result)
        cause = result.reason.cause if result.reason is not None else None
        if not result.force_updated and cause is not Cause.PUSH_NOT_CONFIRMED:
            failed.append(branch)
    survivors = _survivors(repo, slug, sorted(infected), token)
    if failed:
        try:
            unrestored = gitamend.restore_branches(repo, heads, moved, failed)
        except gitamend.AmendUnwindFailed as unwound:
            unrestored = unwound.unrestored
        if unrestored:
            # The pre-push caller already reports this; reporting it here too is the point — the
            # same refused restore was silent on this side, and a local branch left on rewritten
            # history is the operator's problem whether or not any push succeeded.
            survivors.insert(0, Reason(Cause.LEFT_PART_WAY, ", ".join(unrestored)))
    label = (oldest[:12] if len(rebuilt.replaced) == 1
             else f"{len(rebuilt.replaced)} commits from {oldest[:12]}")
    return amended(display, label, tuple(results), tuple(survivors))
