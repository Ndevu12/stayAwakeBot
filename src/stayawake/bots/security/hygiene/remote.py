#!/usr/bin/env python3
"""Repository branch-protection — the only enforced CI gate (needs a GitHub token)."""
from __future__ import annotations

from .models import WORM_GATE_UNCHECKED_ID, HygieneIssue


def check_branch_protection(slug: str | None, token: str | None,
                            branch: str = "main") -> list[HygieneIssue]:
    """Warn if the default branch isn't protected or the Worm Guard check isn't
    required — i.e. the CI gate can be bypassed by a direct push / unchecked merge.
    No-op without a repo slug; a slug that names no repository, or no token, leaves the requirement
    reported as not checked."""
    if not slug:
        return []
    from stayawake.bots.security import guard
    owner, _, name = slug.partition("/")
    if not (owner and name):
        return [_requirement_unchecked(
            slug, branch, f"“{slug}” is not a repository name of the form OWNER/NAME",
            "Run `saw audit --repo OWNER/NAME` with the repository's owner and name.")]
    if not token:
        return [_requirement_unchecked(
            slug, branch, f"No GitHub token was available to read {slug}",
            f"Run `gh auth login` or set GH_SECURITY_TOKEN, then run `saw audit --repo {slug}` again.")]
    from stayawake.lib import github_branch_protection
    prot = github_branch_protection.read(owner, name, branch, token)
    if not prot.protected:
        return [HygieneIssue(
            id="branch-unprotected",
            severity="warning",
            title=f"{slug}@{branch} has no branch protection",
            detail="Anyone with push access can push straight to the default branch, "
                   "bypassing the Worm Guard CI gate entirely.",
            remediation="Protect the branch: require a PR review and the "
                        "'Worm Guard' status check before merging.",
        )]
    contexts = prot.required_checks

    # its ACTUAL job context — a job named `strix` (or anything) produces a context the fuzzy "worm"
    # match below would miss, wrongly flagging a correctly-protected repo. Fall back to the heuristic
    # only when no Strix workflow is found.
    probe = guard.probe_remote_gate(slug, token)
    if probe.cause is not None:
        return [_requirement_unchecked(
            slug, branch,
            f"{slug}@{branch} is protected {prot.held_by}, but its workflows could not be read "
            f"({guard.read_error(slug, probe.cause)})",
            f"Run `saw audit --repo {slug}` again once GitHub can be read.")]
    ref = probe.ref
    if ref is not None:
        if ref.job in contexts:
            return []                                   # the real gate context IS required — good
        return [HygieneIssue(
            id="worm-guard-not-required",
            severity="warning",
            title=f"The Strix gate (“{ref.job}”) is not a required status check on {slug}@{branch}",
            detail=f"The repo runs Strix ({ref.workflow}) and {slug}@{branch} is protected {prot.held_by}, "
                   f"but that does not require its “{ref.job}” check — an infected PR can still merge.",
            remediation=f"Add “{ref.job}” to the required status checks of {prot.settings_named}.",
        )]

    if not any("worm" in (c or "").lower() for c in contexts):
        return [HygieneIssue(
            id="worm-guard-not-required",
            severity="warning",
            title=f"Worm Guard is not a required status check on {slug}@{branch}",
            detail="An infected PR/merge can be merged without the worm scan passing.",
            remediation="Add 'Worm Guard — block infected merges' to the required status checks "
                        f"of {prot.settings_named}.",
        )]
    return []


def _requirement_unchecked(slug: str, branch: str, why: str, remediation: str) -> HygieneIssue:
    """Say that whether a branch requires the worm gate could not be checked. Takes the repository,
    the branch, why, and what to do. Returns the finding."""
    return HygieneIssue(
        id=WORM_GATE_UNCHECKED_ID,
        severity="unknown",
        title=f"Whether {slug}@{branch} requires the worm gate could not be checked",
        detail=f"{why}, so whether an infected PR can merge is unknown.",
        remediation=remediation,
    )
