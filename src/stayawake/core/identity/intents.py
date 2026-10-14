#!/usr/bin/env python3
"""Intents — privileged actions bots/cli want to perform.

Each intent declares the capabilities it requires. The gate checks those before side effects.
"""
from __future__ import annotations

from enum import Enum

from stayawake.core.identity.capabilities import Capability


class Intent(str, Enum):
    READ_REMOTE = "read_remote"
    OPEN_FIX_PR = "open_fix_pr"
    AMEND_REFS = "amend_refs"
    OPEN_GUARD_PR = "open_guard_pr"
    WRITE_ISSUES = "write_issues"
    READ_ADMIN = "read_admin"


_REQUIREMENTS: dict[Intent, frozenset[Capability]] = {
    Intent.READ_REMOTE: frozenset({Capability.REPO_READ}),
    Intent.OPEN_FIX_PR: frozenset({
        Capability.CONTENTS_WRITE, Capability.PULL_REQUESTS_WRITE,
    }),
    Intent.AMEND_REFS: frozenset({Capability.CONTENTS_WRITE}),
    Intent.OPEN_GUARD_PR: frozenset({
        Capability.CONTENTS_WRITE, Capability.PULL_REQUESTS_WRITE,
        Capability.WORKFLOWS_WRITE,
    }),
    Intent.WRITE_ISSUES: frozenset({Capability.ISSUES_WRITE}),
    Intent.READ_ADMIN: frozenset({Capability.ADMIN_READ}),
}


_WHAT_IT_DOES: dict[Intent, str] = {
    Intent.READ_REMOTE: "reading repositories on GitHub",
    Intent.OPEN_FIX_PR: "opening fix pull requests",
    Intent.AMEND_REFS: "replacing infected commits on GitHub",
    Intent.OPEN_GUARD_PR: "opening guard pull requests",
    Intent.WRITE_ISSUES: "filing issues",
    Intent.READ_ADMIN: "reading branch protection",
}


def requirements(intent: Intent) -> frozenset[Capability]:
    return _REQUIREMENTS[intent]


def what_it_does(intent: Intent) -> str:
    """Name what an intent does, in plain words. Takes the intent. Returns the phrase."""
    return _WHAT_IT_DOES[intent]
