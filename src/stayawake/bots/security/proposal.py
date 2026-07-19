#!/usr/bin/env python3
"""Propose a repository change as a real, human-reviewed pull request — with a degradation ladder.

This is the shared GitOps machinery behind commands that don't *impose* a change but *propose* one:
given a git worktree that already has the change committed to a rolling branch, push it and open (or
update) one deduplicated PR — and when the push is refused (no write access, or a branch that
requires signed commits), walk the fallback ladder so the work is never lost: **fork → cross-fork
PR**, else a **git-am-able patch + a deduplicated notify issue**.

It is deliberately domain-neutral: it knows nothing about *what* the change is (a worm remediation,
a CI-gate install, …). Callers build the worktree/commit, the PR title/body and the issue text, then
read the structured `SubmitResult` and render their own human outcome — so domain wording (a
remediation's PARTIAL tag, a gate's hardening checklist) stays with the caller. `saw fix` and
`saw guard setup` are the two callers; the ladder is written once, here.

Never commits to or force-pushes the default branch — the PR is the unit of review.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from stayawake.core.adapters import github_api
from stayawake.core import git as gitutil

PATCHES_DIR = Path("sab-patches")   # where the read-only floor writes .patch files
_FORK_POLL_TRIES = 10               # async fork readiness: poll up to ~30s
_FORK_POLL_DELAY = 3


@dataclass
class IssueSpec:
    """The deduplicated notify issue a caller wants filed when a change can't be PR'd. `label` is
    both the applied label and the dedup key (an existing open issue with it → no duplicate)."""
    title: str
    body: str
    label: str


@dataclass
class SubmitResult:
    """The structured outcome of the submit ladder. Deliberately data-only: the CALLER renders the
    human message from these facts, so domain wording never leaks into this shared seam.

    `kind` is one of:
      "pr"                   — opened/updated a PR on the upstream repo (see `action`)
      "pr-create-failed"     — branch pushed, but the PR API call failed
      "fork-pr"              — opened/updated a cross-fork PR (see `action`, `fork_slug`)
      "fork-not-ready"       — forked, but the fork wasn't queryable in time (`fork_slug`)
      "fork-pr-create-failed"— pushed to the fork, but the PR API call failed (`fork_slug`)
      "floor"                — no push access: `patch_path` and/or `issue_note` record the fallback
    """
    kind: str
    action: str | None = None          # "opened" | "updated" for a pr/fork-pr
    number: int | None = None
    url: str = ""
    fork_slug: str | None = None
    patch_path: Path | None = None
    issue_note: str | None = None      # generic issue outcome fragment, ready to embed


def _wait_for_fork(slug: str, token: str) -> bool:
    """A new fork is created asynchronously; poll until it's queryable (or give up)."""
    owner, name = slug.split("/", 1)
    for attempt in range(_FORK_POLL_TRIES):
        if github_api.get_repo(owner, name, token) is not None:
            return True
        if attempt < _FORK_POLL_TRIES - 1:
            time.sleep(_FORK_POLL_DELAY)
    return False


def _save_patch(wt: Path, slug: str, out_dir: Path) -> Path | None:
    """Capture the committed change as a git-am-able patch so a read-only run (no write access)
    never loses the work when the branch can't be pushed. Returns the path, or None on failure.
    This is the no-write floor of the ladder."""
    patch = gitutil.format_patch(wt, "HEAD")
    if not patch:
        return None
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = (out_dir / (slug.replace("/", "-") + ".patch")).resolve()
        dest.write_text(patch, encoding="utf-8")
    except OSError:
        return None
    return dest


def file_dedup_issue(owner: str, name: str, issue: IssueSpec, token: str) -> str | None:
    """Notify a repo via a de-duplicated issue when a change can't be PR'd. Needs only
    `issues: write`; returns a short generic outcome fragment (ready for the caller to embed), or
    None if it couldn't open one. An existing open issue carrying `issue.label` → no duplicate."""
    try:
        existing = github_api.list_open_issues(owner, name, token, labels=issue.label, quiet=True)
        if existing:
            return f"an open issue already tracks this (#{existing[0].get('number')})"
        created = github_api.create_issue(owner, name, issue.title, issue.body, token,
                                          labels=[issue.label], quiet=True)
        if created and created.get("number"):
            return f"opened issue #{created['number']} ({created.get('html_url', '')})"
    except Exception:  # noqa: BLE001 — notification is best-effort; never mask the patch result
        pass
    return None


def _fork_and_pr(wt: Path, owner: str, name: str, base: str, branch: str,
                 title: str, body: str, token: str) -> SubmitResult | None:
    """When we can't push to the upstream, push the branch to a fork under the authenticated user
    and open a cross-fork PR. Returns a SubmitResult when forking is viable (success OR a post-fork
    failure worth reporting), or None when forking isn't possible so the caller falls through to the
    patch/issue floor.

    Handles: no token identity, can't fork (permissions), forking your own repo, async fork not
    ready, push-to-fork failure, and PR-creation failure."""
    # `get_authenticated_user` (GET /user) is enabledForGitHubApps=false, so an installation token
    # (the Actions GITHUB_TOKEN) returns None here — no fork identity. That's fine: under Actions the
    # upstream push succeeds with `contents: write`, so this fork fallback is never reached. The fork
    # path is for a PAT that lacks upstream write but can fork.
    me = (github_api.get_authenticated_user(token, quiet=True) or {}).get("login")
    if not me or me.lower() == owner.lower():
        return None  # no identity, or it's our own repo (a fork wouldn't help)
    fork = github_api.create_fork(owner, name, token, quiet=True)
    fork_slug = fork.get("full_name") if isinstance(fork, dict) else None
    if not fork_slug or "/" not in fork_slug:
        return None  # forking not permitted → fall back
    if not _wait_for_fork(fork_slug, token):
        return SubmitResult("fork-not-ready", fork_slug=fork_slug)
    # Push the branch to the fork (token via GIT_ASKPASS, never in URL/argv).
    if not gitutil.push_branch(wt, fork_slug, branch, token):
        return None  # couldn't push to the fork either → fall back to patch/issue
    fork_owner = fork_slug.split("/", 1)[0]
    result = github_api.open_or_update_pr(owner, name, head_branch=branch, base=base,
                                          title=title, body=body, token=token, head_owner=fork_owner)
    if not result:
        return SubmitResult("fork-pr-create-failed", fork_slug=fork_slug)
    return SubmitResult("fork-pr", action=result["action"], number=result["number"],
                        url=result.get("html_url", ""), fork_slug=fork_slug)


def submit_change_pr(wt: Path, slug: str, base: str, *, branch: str, title: str, body: str,
                     token: str, issue: IssueSpec | None = None,
                     patches_dir: Path | None = None) -> SubmitResult:
    """Push `branch` (already committed in worktree `wt`) to `slug`'s default-branch review flow and
    open/update one deduplicated PR. On push refusal, walk fork → patch → issue. Returns the
    structured `SubmitResult`; the caller renders the human outcome and reconciles any PR labels.

    `wt` must hold the committed change; `title`/`body` are used for both the upstream and (on
    fallback) the fork PR; `issue`, if given, is filed only when there is no push access."""
    owner, name = slug.split("/", 1)
    # Token via GIT_ASKPASS (env), never in the URL/argv. Push the change branch.
    if not gitutil.push_branch(wt, slug, branch, token):
        # Push rejected — usually no write access, but a branch that REQUIRES SIGNED COMMITS also
        # rejects a possibly-unsigned commit here. Either way, fall back: fork→PR, else patch +
        # de-duplicated issue so the work is never lost.
        forked = _fork_and_pr(wt, owner, name, base, branch, title, body, token)
        if forked is not None:
            return forked
        patch = _save_patch(wt, slug, Path(patches_dir) if patches_dir else PATCHES_DIR)
        note = file_dedup_issue(owner, name, issue, token) if issue else None
        return SubmitResult("floor", patch_path=patch, issue_note=note)

    # Open the rolling PR or refresh the existing one (idempotent dedup lives in open_or_update_pr).
    result = github_api.open_or_update_pr(owner, name, head_branch=branch, base=base,
                                          title=title, body=body, token=token)
    if not result:
        return SubmitResult("pr-create-failed")
    return SubmitResult("pr", action=result["action"], number=result["number"],
                        url=result.get("html_url", ""))
