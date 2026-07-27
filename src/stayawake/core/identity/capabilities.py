#!/usr/bin/env python3
"""Capability vocabulary — what a GitHub credential is allowed to do.

Capabilities are AuthZ atoms. Intents declare the set they need; the gate checks the
session can supply them before any privileged side effect runs.
"""
from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    REPO_READ = "repo_read"
    CONTENTS_WRITE = "contents_write"
    PULL_REQUESTS_WRITE = "pull_requests_write"
    WORKFLOWS_WRITE = "workflows_write"
    ISSUES_WRITE = "issues_write"
    FORK = "fork"
    ADMIN_READ = "admin_read"


# Classic OAuth scope → capabilities it grants (coarse but reliable for `gh` / classic PATs).
_SCOPE_GRANTS: dict[str, frozenset[Capability]] = {
    "repo": frozenset({
        Capability.REPO_READ, Capability.CONTENTS_WRITE, Capability.PULL_REQUESTS_WRITE,
        Capability.ISSUES_WRITE, Capability.FORK, Capability.ADMIN_READ,
    }),
    "public_repo": frozenset({
        Capability.REPO_READ, Capability.CONTENTS_WRITE, Capability.PULL_REQUESTS_WRITE,
        Capability.ISSUES_WRITE, Capability.FORK,
    }),
    "workflow": frozenset({Capability.WORKFLOWS_WRITE}),
    "read:org": frozenset({Capability.REPO_READ}),
    "gist": frozenset(),
}


def capabilities_from_oauth_scopes(scopes: frozenset[str] | set[str]) -> frozenset[Capability]:
    """Map classic OAuth scope names to capabilities. Unknown scope names are ignored."""
    out: set[Capability] = set()
    for s in scopes:
        out |= _SCOPE_GRANTS.get(s.strip().lower(), frozenset())
    return frozenset(out)


# GitHub App installation permission name → capability at write (or read) level.
_APP_PERM_WRITE: dict[str, Capability] = {
    "contents": Capability.CONTENTS_WRITE,
    "pull_requests": Capability.PULL_REQUESTS_WRITE,
    "workflows": Capability.WORKFLOWS_WRITE,
    "issues": Capability.ISSUES_WRITE,
    "administration": Capability.ADMIN_READ,
}
_APP_PERM_READ: dict[str, Capability] = {
    "contents": Capability.REPO_READ,
    "metadata": Capability.REPO_READ,
    "administration": Capability.ADMIN_READ,
}


def capabilities_from_app_permissions(perms: dict[str, str]) -> frozenset[Capability]:
    """Map a GitHub App installation `permissions` object to capabilities."""
    out: set[Capability] = {Capability.REPO_READ}  # metadata is always granted on install
    for name, level in (perms or {}).items():
        key = name.lower()
        lvl = (level or "").lower()
        if lvl == "write":
            if key in _APP_PERM_WRITE:
                out.add(_APP_PERM_WRITE[key])
            if key in _APP_PERM_READ:
                out.add(_APP_PERM_READ[key])
        elif lvl == "read":
            if key in _APP_PERM_READ:
                out.add(_APP_PERM_READ[key])
    # Apps that can write contents can typically fork when the target allows it.
    if Capability.CONTENTS_WRITE in out:
        out.add(Capability.FORK)
    return frozenset(out)
