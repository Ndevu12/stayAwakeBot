#!/usr/bin/env python3
"""AuthZ decisions and upgrade paths — structured outcomes, never a bare bool."""
from __future__ import annotations

from dataclasses import dataclass, field

from stayawake.core.identity.capabilities import Capability
from stayawake.core.identity.intents import Intent


@dataclass(frozen=True)
class UpgradePath:
    """How the operator can gain the missing capability."""
    kind: str
    detail: str = ""
    scopes: tuple[str, ...] = ()
    command: str = ""


@dataclass(frozen=True)
class Decision:
    """Gate result. `allowed` means privileged work may proceed; otherwise stop and render."""
    allowed: bool
    intent: Intent
    missing: frozenset[Capability] = field(default_factory=frozenset)
    reason: str = ""
    upgrades: tuple[UpgradePath, ...] = ()
    session_source: str | None = None
    session_actor: str | None = None

    @property
    def message(self) -> str:
        """Human-facing multi-line summary for CLI stderr / progress lines."""
        if self.allowed:
            who = self.session_actor or self.session_source or "credential"
            return f"authz ok for {self.intent.value} (as {who})"
        lines = [self.reason or f"not authorized for {self.intent.value}"]
        if self.missing:
            lines.append("missing: " + ", ".join(sorted(c.value for c in self.missing)))
        for u in self.upgrades:
            if u.command:
                lines.append(f"  → {u.detail}: `{u.command}`" if u.detail else f"  → `{u.command}`")
            elif u.detail:
                lines.append(f"  → {u.detail}")
        return "\n".join(lines)


def upgrades_for_missing(missing: frozenset[Capability], *, source: str | None) -> tuple[UpgradePath, ...]:
    """Default upgrade ladder when capabilities are known-missing."""
    paths: list[UpgradePath] = []
    need_workflow = Capability.WORKFLOWS_WRITE in missing
    need_write = bool(missing & {
        Capability.CONTENTS_WRITE, Capability.PULL_REQUESTS_WRITE, Capability.ISSUES_WRITE,
    })
    if source in (None,):
        paths.append(UpgradePath(
            kind="login",
            detail="authenticate first",
            command="gh auth login   # or: saw auth app register",
        ))
        return tuple(paths)
    if need_workflow:
        scopes = ("repo", "workflow") if need_write or source == "gh" else ("workflow",)
        if source == "gh":
            paths.append(UpgradePath(
                kind="refresh_gh",
                detail="GitHub rejects workflow-file pushes without the `workflow` scope",
                scopes=scopes,
                command=f"gh auth refresh -h github.com -s {','.join(scopes)}",
            ))
        paths.append(UpgradePath(
            kind="register_app",
            detail="or register a StayAwakeBot GitHub App with Workflows: write (recommended for fleet)",
            command="saw auth app register",
        ))
        if source != "gh":
            paths.append(UpgradePath(
                kind="pat_scopes",
                detail="classic PAT needs `workflow`; fine-grained needs Workflows: Read and write",
                scopes=("workflow",),
            ))
    elif need_write and source == "gh":
        paths.append(UpgradePath(
            kind="refresh_gh",
            detail="token needs repo write + pull-request access",
            scopes=("repo",),
            command="gh auth refresh -h github.com -s repo",
        ))
    elif need_write:
        paths.append(UpgradePath(
            kind="pat_scopes",
            detail="grant Contents + Pull requests: Read and write (or classic `repo`)",
            scopes=("repo",),
        ))
        paths.append(UpgradePath(
            kind="register_app",
            detail="or use a StayAwakeBot GitHub App installation with those permissions",
            command="saw auth app register",
        ))
    if not paths:
        paths.append(UpgradePath(
            kind="register_app",
            detail="register a StayAwakeBot GitHub App with the required permissions",
            command="saw auth app register",
        ))
    return tuple(paths)
