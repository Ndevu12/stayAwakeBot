#!/usr/bin/env python3
"""Read what GitHub enforces on a branch: its classic branch protection and the active rules of every
ruleset that applies to it."""
from __future__ import annotations

from dataclasses import dataclass

from stayawake.lib.adapters import github_api


@dataclass(frozen=True)
class BranchProtection:
    """What protects a branch, and the status checks it requires before a change lands."""

    by_classic: bool = False
    by_ruleset: bool = False
    required_checks: frozenset[str] = frozenset()

    @property
    def protected(self) -> bool:
        """Tell whether anything protects the branch."""
        return self.by_classic or self.by_ruleset

    @property
    def held_by(self) -> str:
        """Name what protects the branch, as `protected <this>` reads."""
        if self.by_classic and self.by_ruleset:
            return "by branch protection and a ruleset"
        return "by a ruleset" if self.by_ruleset else "by branch protection"

    @property
    def settings_named(self) -> str:
        """Name the settings that hold the branch's required status checks."""
        if self.by_classic and self.by_ruleset:
            return "its branch protection or the ruleset that protects it"
        return "the ruleset that protects it" if self.by_ruleset else "its branch protection"


class _Malformed(ValueError):
    """GitHub's answer does not have the shape its API describes."""


def _listed(value) -> list:
    """Return a list field as a list. Takes its value. Returns [] for an absent one; raises
    _Malformed for one that is not a list."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise _Malformed(type(value).__name__)
    return value


def _classic_checks(classic: dict) -> set[str]:
    required = classic.get("required_status_checks")
    if required is None:
        return set()
    if not isinstance(required, dict):
        raise _Malformed(type(required).__name__)
    contexts = {c for c in _listed(required.get("contexts")) if isinstance(c, str)}
    return contexts | {c.get("context") for c in _listed(required.get("checks"))
                       if isinstance(c, dict) and isinstance(c.get("context"), str)}


def _ruleset_checks(rules: list[dict]) -> set[str]:
    contexts: set[str] = set()
    for rule in rules:
        parameters = rule.get("parameters")
        if rule["type"] != "required_status_checks" or not isinstance(parameters, dict):
            continue
        contexts |= {c.get("context") for c in _listed(parameters.get("required_status_checks"))
                     if isinstance(c, dict) and isinstance(c.get("context"), str)}
    return contexts


def from_settings(classic: dict | None, rules: list | None) -> BranchProtection:
    """Grade a branch's protection. Takes its classic branch protection (None when it has none or it
    could not be read) and the active rules that apply to it (None when they could not be read).
    Either one read in a shape GitHub's API does not describe counts as unread. Returns what
    protects it and the checks it requires."""
    classic = classic if isinstance(classic, dict) else None
    try:
        classic_checks = _classic_checks(classic) if classic else set()
    except _Malformed:
        classic, classic_checks = None, set()
    active = [r for r in rules if isinstance(r, dict) and isinstance(r.get("type"), str)] if isinstance(
        rules, list) else []
    try:
        ruleset_checks = _ruleset_checks(active)
    except _Malformed:
        active, ruleset_checks = [], set()
    return BranchProtection(by_classic=classic is not None, by_ruleset=bool(active),
                            required_checks=frozenset(classic_checks | ruleset_checks))


def read(owner: str, repo: str, branch: str, token: str | None) -> BranchProtection:
    """Read and grade a branch's protection from GitHub. Takes the owner, the repository, the branch
    and the token. Returns what protects it; rules that could not be read count as none."""
    classic = github_api.get_branch_protection(owner, repo, branch, token)
    rules = github_api.get_branch_rules(owner, repo, branch, token)
    return from_settings(classic, rules.value if rules.cause is None else None)
