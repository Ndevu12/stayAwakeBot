#!/usr/bin/env python3
"""`saw fix amend` — replace past commits that still carry the payload, then force-update
each branch they sat on when this identity may. Never `--pr`. Never moves a tag.

Bare `saw fix` is unchanged.
"""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.lib.adapters import github_api
from stayawake.lib.git.auth import github_https_auth
from stayawake.lib.git.run import NETWORK_TIMEOUT, run
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write.push import PushResult
from stayawake.lib import git as gitutil


ALLOWED = "allowed"
PROTECTED = "protected"
UNKNOWN = "unknown"


def _full(repo: Path, sha: str) -> str:
    return gitutil.stdout(repo, ["rev-parse", sha]).strip() or sha


def _confirmed_commits(scan) -> list:
    found = []
    seen: set[str] = set()
    for f in scan.findings:
        if getattr(f, "vector", None) != "evil-merge":
            continue
        if getattr(f, "confidence", None) != CONFIRMED:
            continue
        sha = getattr(f, "commit_sha", None) or getattr(f, "path", None)
        if not sha or sha in seen:
            continue
        seen.add(sha)
        found.append(f)
    return found


def force_update_state(owner: str, repo: str, branch: str, token: str | None) -> str:
    """Whether this identity may force-update `branch`. Read, never by attempting a push."""
    if not token:
        return UNKNOWN
    br = github_api.read_branch(owner, repo, branch, token)
    if br.cause == "not_found":
        return ALLOWED
    if br.cause is not None or not isinstance(br.value, dict):
        return UNKNOWN
    if not br.value.get("protected"):
        return ALLOWED
    prot = github_api.read_branch_protection(owner, repo, branch, token)
    if prot.cause is not None or not isinstance(prot.value, dict):
        return UNKNOWN
    if (prot.value.get("allow_force_pushes") or {}).get("enabled") is True:
        return ALLOWED
    return PROTECTED


def _remote_sha(repo: Path, slug: str, branch: str, token: str | None) -> tuple[bool, str | None]:
    """`(readable, sha)`. `sha` is None when the branch is absent. `readable` False is unknown."""
    with github_https_auth(token) as (prefix, env):
        res = run(repo, ["ls-remote", "--heads", f"{prefix}{slug}.git", f"refs/heads/{branch}"],
                  env=env, timeout=NETWORK_TIMEOUT)
    if res is None or res.returncode != 0:
        return False, None
    lines = [ln for ln in (res.stdout or "").splitlines() if ln.strip()]
    if not lines:
        return True, None
    return True, lines[0].split()[0]


def _push_amended(repo: Path, slug: str, local_branch: str, token: str | None,
                  remote_branch: str, lease: str | None) -> PushResult:
    return gitutil.push_branch_result(
        repo, slug, local_branch, token,
        force=True,
        remote_branch=remote_branch,
        lease=lease)


def _publish_branch(repo: Path, slug: str, branch: str, token: str | None, *,
                    force_update, pusher) -> tuple[str, bool]:
    """One branch. Returns (operator note, whether this ref was fully updated on the remote)."""
    state = force_update(branch)
    if state == UNKNOWN:
        return (f"rights to update '{branch}' could not be established", False)
    dest = branch if state == ALLOWED else f"saw-amend/{branch}"
    if pusher is None:
        readable, lease = _remote_sha(repo, slug, dest, token)
        if not readable:
            return (f"rights to update '{branch}' could not be established", False)
        result = _push_amended(repo, slug, branch, token, dest,
                               lease if state == ALLOWED else None)
    else:
        result = pusher(branch, dest, None)
    if not result.ok:
        return (f"'{branch}' was not force-updated", False)
    if state == PROTECTED:
        return (f"'{branch}' is protected — pushed '{dest}'", False)
    return (f"force-updated '{branch}'", True)


def amend_repo(repo: Path, opts, signatures, allowlist, token: str | None = None, *,
               force_update=None, pusher=None) -> str:
    """Replace confirmed past-commit payload on every branch that still reaches it, then
    force-update those branches when this identity may. Returns the operator line."""
    display = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    if not gitutil.is_git_repo(repo):
        return f"{display}: not a git repository"
    if gitamend.is_dirty(repo):
        return f"{display}: working tree is not clean — commit or stash first"

    scan = scan_target(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)
    if scan.error:
        return f"{display}: scan did not finish — nothing was replaced"
    commits = _confirmed_commits(scan)
    if not commits:
        return f"{display}: no confirmed payload in past commits to replace"
    if len(commits) > 1:
        shas = ", ".join(_full(repo, getattr(f, "commit_sha", None) or f.path)[:12] for f in commits)
        return (f"{display}: {len(commits)} confirmed past commits "
                f"— not replaced ({shas})")

    finding = commits[0]
    old = _full(repo, finding.commit_sha or finding.path)
    heads = gitamend.carrying_branches(repo, old)
    if not heads:
        return (f"{display}: confirmed commit {old[:12]} is not on any branch "
                "— nothing was replaced")

    related = tuple(getattr(finding, "related_paths", ()) or ())
    new = gitamend.reconstruct_merge(repo, old)
    if new is None:
        return (f"{display}: could not replace commit {old[:12]} "
                "— a clean version could not be established")

    capture = {name: tip for name, tip, _ in heads}
    gitamend.capture_bundle(repo, old, related, capture)
    tags = gitutil.stdout(repo, ["tag", "--points-at", old]).split()
    moved = gitamend.apply_replacement(repo, old, new, heads)
    if moved is None:
        names = ", ".join(repr(n) for n, _, _ in heads)
        return f"{display}: replay failed — {names} left as they stood"

    named = ", ".join(repr(n) for n in moved)
    n_later = max((len(gitamend.descendant_shas(repo, old, tip)) for _, tip, _ in heads), default=0)
    after = (f"{n_later} later commit(s) replayed" if n_later else "branches now point at the replacement")
    line = f"{display}: replaced commit {old[:12]} on {named} ({after})"

    slug = gitutil.origin_slug(repo)
    if slug and (token or force_update is not None):
        owner, name = slug.split("/", 1)
        fu = force_update or (lambda b, _o=owner, _n=name: force_update_state(_o, _n, b, token))
        notes = []
        complete = True
        for branch in moved:
            note, ok = _publish_branch(repo, slug, branch, token, force_update=fu, pusher=pusher)
            notes.append(note)
            complete = complete and ok
        line += "; " + "; ".join(notes)
        if not complete:
            line += ". The remote was not fully updated"
    elif slug:
        line += "; rights to update the remote could not be established. The remote was not fully updated"

    tag_note = "; tags still point at the previous commit" if tags else ""
    return (f"{line}. The previous objects remain until collected; forks are unaffected"
            f"{tag_note}")
