#!/usr/bin/env python3
"""Repository branch-protection — the only enforced CI gate (needs a GitHub token)."""
from __future__ import annotations

from .models import HygieneIssue


def check_branch_protection(slug: str | None, token: str | None,
                            branch: str = "main") -> list[HygieneIssue]:
    """Warn if the default branch isn't protected or the Worm Guard check isn't
    required — i.e. the CI gate can be bypassed by a direct push / unchecked merge.
    No-op without a repo slug and token."""
    if not slug or "/" not in slug or not token:
        return []
    from stayawake.lib.adapters import github_api
    owner, name = slug.split("/", 1)
    prot = github_api.get_branch_protection(owner, name, branch, token)
    if prot is None:
        return [HygieneIssue(
            id="branch-unprotected",
            severity="warning",
            title=f"{slug}@{branch} has no branch protection",
            detail="Anyone with push access can push straight to the default branch, "
                   "bypassing the Worm Guard CI gate entirely.",
            remediation="Protect the branch: require a PR review and the "
                        "'Worm Guard' status check before merging.",
        )]
    rsc = prot.get("required_status_checks") or {}
    contexts = set(rsc.get("contexts") or [])
    contexts |= {c.get("context") for c in (rsc.get("checks") or []) if isinstance(c, dict)}

    # Prefer the PRECISE check (#1230): find the repo's Strix gate by its action reference and require
    # its ACTUAL job context — a job named `strix` (or anything) produces a context the fuzzy "worm"
    # match below would miss, wrongly flagging a correctly-protected repo. Fall back to the heuristic
    # only when no Strix workflow is found (or its workflows can't be read).
    from stayawake.bots.security import guard
    ref = guard.remote_gate(slug, token)
    if ref is not None:
        if ref.job in contexts:
            return []                                   # the real gate context IS required — good
        return [HygieneIssue(
            id="worm-guard-not-required",
            severity="warning",
            title=f"The Strix gate (“{ref.job}”) is not a required status check on {slug}@{branch}",
            detail=f"The repo runs Strix ({ref.workflow}), but branch protection does not require its "
                   f"“{ref.job}” check — an infected PR can still merge.",
            remediation=f"Add “{ref.job}” to the branch's required status checks.",
        )]

    if not any("worm" in (c or "").lower() for c in contexts):
        return [HygieneIssue(
            id="worm-guard-not-required",
            severity="warning",
            title=f"Worm Guard is not a required status check on {slug}@{branch}",
            detail="An infected PR/merge can be merged without the worm scan passing.",
            remediation="Add 'Worm Guard — block infected merges' to the branch's "
                        "required status checks.",
        )]
    return []


