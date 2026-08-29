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
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write.push import PushResult
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


def _remote_sha(repo: Path, slug: str, branch: str, token: str | None) -> str | None:
    with github_https_auth(token) as (prefix, env):
        res = run(repo, ["ls-remote", "--heads", f"{prefix}{slug}.git", f"refs/heads/{branch}"],
                  env=env, timeout=NETWORK_TIMEOUT)
    if res is None or res.returncode != 0:
        return None
    lines = [ln for ln in (res.stdout or "").splitlines() if ln.strip()]
    if not lines:
        return None
    return lines[0].split()[0]


def _push_amended(repo: Path, slug: str, branch: str, token: str | None,
                  lease: str | None) -> PushResult:
    return gitutil.push_branch_result(
        repo, slug, branch, token, force=True, remote_branch=branch, lease=lease)


def _force_update_branch(repo: Path, slug: str, branch: str, token: str | None, *,
                         pusher) -> tuple[str, bool]:
    if pusher is None:
        lease = _remote_sha(repo, slug, branch, token)
        result = _push_amended(repo, slug, branch, token, lease)
        if result.ok:
            remote = _remote_sha(repo, slug, branch, token)
            local = gitutil.stdout(repo, ["rev-parse", f"refs/heads/{branch}"]).strip()
            if not remote or not local or remote != local:
                result = PushResult(False)
    else:
        result = pusher(branch, branch, None)
    if not result.ok:
        return (f"'{branch}' was not force-updated", False)
    return (f"force-updated '{branch}'", True)


def amend_repo(repo: Path, opts, signatures, allowlist, token: str | None = None, *,
               pusher=None) -> str:
    """Force-update every branch that still reaches a confirmed past-commit payload.

    The local rewrite is a step. The result is the remote refs moving. Returns one operator line.
    """
    display = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    if not gitutil.is_git_repo(repo):
        return f"{display}: not a git repository"
    if gitamend.is_dirty(repo):
        return f"{display}: working tree is not clean — commit or stash first"

    slug = gitutil.origin_slug(repo)
    if not slug:
        return f"{display}: no remote — nothing was force-updated"
    if not (token or "").strip() and pusher is None:
        return f"{display}: no credential — nothing was force-updated"

    scan = scan_target(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)
    if scan.error is not None:
        return f"{display}: scan did not finish — nothing was force-updated"
    commits = _confirmed_commits(scan)
    if not commits:
        return f"{display}: no confirmed payload in past commits to replace"
    if len(commits) > 1:
        shas = ", ".join((_full(repo, getattr(f, "commit_sha", None) or "") or f.path)[:12]
                         for f in commits)
        return (f"{display}: {len(commits)} confirmed past commits "
                f"— nothing was force-updated ({shas})")

    finding = commits[0]
    old = _full(repo, finding.commit_sha or "")
    if not old:
        return f"{display}: confirmed commit is not a commit — nothing was force-updated"
    heads = gitamend.carrying_branches(repo, old)
    if not heads:
        return (f"{display}: confirmed commit {old[:12]} is not on any branch "
                "— nothing was force-updated")

    related = tuple(getattr(finding, "related_paths", ()) or ())
    new = gitamend.reconstruct_merge(repo, old)
    if new is None:
        return (f"{display}: could not replace commit {old[:12]} "
                "— nothing was force-updated")

    capture = {name: tip for name, tip, _ in heads}
    gitamend.capture_bundle(repo, old, related, capture)
    tags = gitutil.stdout(repo, ["tag", "--points-at", old]).split()
    moved = gitamend.apply_replacement(repo, old, new, heads)
    if moved is None:
        names = ", ".join(repr(n) for n, _, _ in heads)
        return f"{display}: replay failed — {names} left as they stood; nothing was force-updated"

    notes = []
    complete = True
    failed: list[str] = []
    for branch in moved:
        note, ok = _force_update_branch(repo, slug, branch, token, pusher=pusher)
        notes.append(note)
        complete = complete and ok
        if not ok:
            failed.append(branch)
    if failed:
        gitamend.restore_branches(repo, heads, moved, failed)
    line = f"{display}: {'; '.join(notes)} (commit {old[:12]})"
    if not complete:
        line += ". The remote was not fully updated"
    tag_note = "; tags still point at the previous commit" if tags else ""
    return (f"{line}. The previous objects remain until collected; forks are unaffected"
            f"{tag_note}")
