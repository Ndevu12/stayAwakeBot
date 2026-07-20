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
indicator scanning lives in the scanner/service; this is complementary. Probes are stdlib-only and
degrade gracefully when a path/tool is absent — the one exception is the opt-in
`--verify` content-scan, which delegates to the scanner engine via a LAZY import so the
default audit never pulls it in (see host_artifacts.check_host_artifacts).
"""
from __future__ import annotations

import subprocess          # noqa: F401  re-exported so tests can patch hygiene.subprocess.run globally
from pathlib import Path   # noqa: F401  re-exported so tests can patch hygiene.Path.home globally
from typing import Callable

from .models import (HygieneIssue, INCIDENT_TRIGGER_IDS, ACTIVE_PERSISTENCE_IDS,
                     CREDENTIAL_EXPOSURE_IDS, incident_response_sequence, credential_exposure_note)
from .credentials import check_credentials
from .runner import check_runner_persistence
from .os_service import check_persistence
from .host_artifacts import check_host_artifacts
from .editor import check_vscode
from .mechanism import check_ssh_authorized_keys, check_shell_profile, check_git_config_execution
from .remote import check_branch_protection
from stayawake.utils.render import SEVERITY, block, marked_list, paint

__all__ = [
    "HygieneIssue", "INCIDENT_TRIGGER_IDS", "incident_response_sequence",
    "check_credentials", "check_runner_persistence", "check_persistence", "check_host_artifacts",
    "check_vscode", "check_ssh_authorized_keys", "check_shell_profile", "check_git_config_execution",
    "check_branch_protection", "audit", "audit_checks", "render",
]

def audit(slug: str | None = None, token: str | None = None,
          branch: str = "main", *, verify_artifacts: bool = False) -> list[HygieneIssue]:
    """Run every local-posture check and return the combined issue list (non-streaming).

    Delegates to audit_checks() so the SINGLE definition of what an audit runs is shared with the
    streaming CLI — neither may hand-assemble its own subset (that omission is how a probe once got
    silently dropped)."""
    issues: list[HygieneIssue] = []
    for _label, check in audit_checks(slug, token, branch, verify_artifacts=verify_artifacts):
        issues += check()
    return issues


def audit_checks(slug: str | None = None, token: str | None = None, branch: str = "main",
                 *, verify_artifacts: bool = False
                 ) -> list[tuple[str, Callable[[], list[HygieneIssue]]]]:
    """The ordered (label, check) probes that make up an audit — the ONE definition of what
    `saw audit` runs, consumed by both audit() (all-at-once) and the streaming CLI (per-check
    spinner). Each `check` is a zero-arg callable returning list[HygieneIssue]. When a repo `slug`
    and `token` are supplied, the branch-protection gate on `branch` is included. `verify_artifacts`
    (the `--verify` opt-in) lets the host-artifact probe content-scan a lone weak dir."""
    return [
        ("cached credentials", check_credentials),
        ("VS Code settings", check_vscode),
        ("self-hosted runner", check_runner_persistence),
        ("OS-service persistence", check_persistence),
        ("host drop-files", lambda: check_host_artifacts(verify=verify_artifacts)),
        ("SSH authorized_keys", check_ssh_authorized_keys),
        ("shell startup files", check_shell_profile),
        ("git exec config", check_git_config_execution),
        ("branch protection", lambda: check_branch_protection(slug, token, branch)),
    ]


_ICON = {"warning": "⚠️", "info": "•"}


def _banner(issue_ids: set[str], *, color: bool, width: int) -> list[str]:
    """The incident banner, GRADED to the evidence (proportionality — see models): the full
    isolate → rebuild → rotate-LAST runbook leads ONLY on active host persistence; a lone
    credential EXPOSURE gets a calm, proportionate note (not "isolate and rebuild" over a cached
    token); hygiene / info-only findings get no banner. Empty list when none is warranted.

    The runbook is a genuine ORDERED procedure (rotate LAST) → a NUMBERED list; the note is a set
    of points/caveats, not a sequence → a BULLETED list. Both go through core.render.marked_list."""
    if issue_ids & ACTIVE_PERSISTENCE_IDS:
        head = "⚠️  Active host persistence detected — respond in THIS order (rotate LAST):"
        steps, ordered = incident_response_sequence(), True
    elif issue_ids & CREDENTIAL_EXPOSURE_IDS:
        head = "⚠️  Credential exposure — no active host persistence detected:"
        steps, ordered = credential_exposure_note(), False
    else:
        return []
    return ([paint(head, SEVERITY["warning"], on=color)] +
            marked_list(steps, ordered=ordered, indent=5, width=width))


def render(issues: list[HygieneIssue], *, color: bool = False, width: int = 80) -> str:
    """Human-facing audit report. `color` (ANSI, gated by the caller via
    core.terminal.supports_color) and `width` (terminal columns, from core.render.term_width)
    default to plain/80 so a piped or test invocation is deterministic. Findings are grouped
    worst-first (warnings to act on, then weaker items to review); long detail/fix/runbook lines
    wrap to `width` with a hanging indent."""
    if not issues:
        return paint("✓ Local security hygiene: no issues found.", SEVERITY["ok"], on=color)

    warnings = [i for i in issues if i.severity == "warning"]
    reviews = [i for i in issues if i.severity != "warning"]
    counts = []
    if warnings:
        counts.append(f"{len(warnings)} warning{'' if len(warnings) == 1 else 's'}")
    if reviews:
        counts.append(f"{len(reviews)} to review")
    n = len(issues)
    lines = [f"Local security hygiene — {n} finding{'' if n == 1 else 's'}: " + ", ".join(counts), ""]

    banner = _banner({i.id for i in issues}, color=color, width=width)
    if banner:
        lines += banner + [""]

    # Group headers only when BOTH tiers are present (otherwise the counts line already says which).
    show_headers = bool(warnings) and bool(reviews)
    for gtitle, gsub, gsev, items in (
            ("WARNINGS", "act on these", "warning", warnings),
            ("TO REVIEW", "weaker signals to verify / hygiene", "info", reviews)):
        if not items:
            continue
        if show_headers:
            lines.append(paint(gtitle, SEVERITY[gsev], on=color) +
                         paint(f"  · {gsub}", SEVERITY["info"], on=color))
        for i in items:
            code = SEVERITY.get(i.severity)
            icon = _ICON.get(i.severity, "•")
            lines.append(f"  {paint(icon, code, on=color)} {paint(i.title, code, on=color)}")
            lines += block(i.detail, indent=5, width=width)
            lines += block(i.remediation, indent=5, width=width, marker="→ fix  ",
                           code=SEVERITY["info"], color=color)
            lines.append("")
    return "\n".join(lines).rstrip()
