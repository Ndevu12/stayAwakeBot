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
    OPEN_GUARD_PR = "open_guard_pr"
    WRITE_ISSUES = "write_issues"
    READ_ADMIN = "read_admin"


_REQUIREMENTS: dict[Intent, frozenset[Capability]] = {
    Intent.READ_REMOTE: frozenset({Capability.REPO_READ}),
    Intent.OPEN_FIX_PR: frozenset({
        Capability.CONTENTS_WRITE, Capability.PULL_REQUESTS_WRITE,
    }),
    Intent.OPEN_GUARD_PR: frozenset({
        Capability.CONTENTS_WRITE, Capability.PULL_REQUESTS_WRITE,
        Capability.WORKFLOWS_WRITE,
    }),
    Intent.WRITE_ISSUES: frozenset({Capability.ISSUES_WRITE}),
    Intent.READ_ADMIN: frozenset({Capability.ADMIN_READ}),
}


def requirements(intent: Intent) -> frozenset[Capability]:
    return _REQUIREMENTS[intent]
