#!/usr/bin/env python3
"""Local machine security-posture checks (the "harden the surface" layer).

Single responsibility: inspect the *developer machine* — not repositories — for the worm's entry and
propagation surfaces, and report actionable hygiene issues. Split per concern into this package:

  * credentials    — a cached GitHub token (Keychain / ~/.git-credentials)
  * runner         — a self-hosted Actions runner (rotation-surviving foothold)
  * os_service     — a planted OS service / launch agent (the rotation wiper)
  * host_artifacts — staged ingress tooling / exfil drop-files
  * editor         — VS Code auto-run tasks + Workspace Trust
  * mechanism      — wave-agnostic sinks: ~/.ssh, shell startup files, exec-on-git-command config (#1161)
  * remote         — repository branch protection (the only enforced CI gate)

`audit_checks()` here is the SINGLE composition site — neither `audit()` nor the streaming CLI may
hand-assemble its own subset (that omission is how a probe once got silently dropped). Repository
indicator scanning lives in the scanner/service; this is complementary. Stdlib only; every probe
degrades gracefully when a path/tool is absent.
"""
from __future__ import annotations

import subprocess          # noqa: F401  re-exported so tests can patch hygiene.subprocess.run globally
from pathlib import Path   # noqa: F401  re-exported so tests can patch hygiene.Path.home globally
from typing import Callable

from .models import HygieneIssue, INCIDENT_TRIGGER_IDS, incident_response_sequence
from .credentials import check_credentials
from .runner import check_runner_persistence
from .os_service import check_persistence
from .host_artifacts import check_host_artifacts
from .editor import check_vscode
from .mechanism import check_ssh_authorized_keys, check_shell_profile, check_git_config_execution
from .remote import check_branch_protection

__all__ = [
    "HygieneIssue", "INCIDENT_TRIGGER_IDS", "incident_response_sequence",
    "check_credentials", "check_runner_persistence", "check_persistence", "check_host_artifacts",
    "check_vscode", "check_ssh_authorized_keys", "check_shell_profile", "check_git_config_execution",
    "check_branch_protection", "audit", "audit_checks", "render",
]

def audit(slug: str | None = None, token: str | None = None,
          branch: str = "main") -> list[HygieneIssue]:
    """Run every local-posture check and return the combined issue list (non-streaming).

    Delegates to audit_checks() so the SINGLE definition of what an audit runs is shared with the
    streaming CLI — neither may hand-assemble its own subset (that omission is how a probe once got
    silently dropped)."""
    issues: list[HygieneIssue] = []
    for _label, check in audit_checks(slug, token, branch):
        issues += check()
    return issues


def audit_checks(slug: str | None = None, token: str | None = None,
                 branch: str = "main") -> list[tuple[str, Callable[[], list[HygieneIssue]]]]:
    """The ordered (label, check) probes that make up an audit — the ONE definition of what
    `saw audit` runs, consumed by both audit() (all-at-once) and the streaming CLI (per-check
    spinner). Each `check` is a zero-arg callable returning list[HygieneIssue]. When a repo `slug`
    and `token` are supplied, the branch-protection gate on `branch` is included."""
    return [
        ("cached credentials", check_credentials),
        ("VS Code settings", check_vscode),
        ("self-hosted runner", check_runner_persistence),
        ("OS-service persistence", check_persistence),
        ("host drop-files", check_host_artifacts),
        ("SSH authorized_keys", check_ssh_authorized_keys),
        ("shell startup files", check_shell_profile),
        ("git exec config", check_git_config_execution),
        ("branch protection", lambda: check_branch_protection(slug, token, branch)),
    ]


def render(issues: list[HygieneIssue]) -> str:
    if not issues:
        return "✓ Local security hygiene: no issues found."
    icon = {"warning": "⚠️", "info": "•"}
    lines = [f"Local security hygiene — {len(issues)} item(s):", ""]
    # Credential exposure / host persistence present → lead with the ordered runbook so the
    # user rotates LAST (rotating while persistence is live can trip the wiper).
    if any(i.id in INCIDENT_TRIGGER_IDS for i in issues):
        lines.append("⚠️  Credential exposure or active host persistence detected — "
                     "respond in THIS order (rotate LAST):")
        lines += [f"     {step}" for step in incident_response_sequence()]
        lines.append("")
    for i in issues:
        lines.append(f"{icon.get(i.severity, '•')}  [{i.severity}] {i.title}")
        lines.append(f"     {i.detail}")
        lines.append(f"     fix: {i.remediation}")
        lines.append("")
    return "\n".join(lines).rstrip()
