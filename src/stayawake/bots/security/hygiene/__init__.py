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
                     CREDENTIAL_EXPOSURE_IDS, UNVERIFIED_PERSISTENCE_IDS, ROTATION_UNSAFE_IDS,
                     ROTATION_SAFE, ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_UNKNOWN,
                     rotation_safety, incident_response_sequence, credential_exposure_note)
from .credentials import check_credentials
from .runner import check_runner_persistence
from .os_service import check_persistence
from .coverage import check_persistence_coverage
from .autorun import check_autorun
from .host_artifacts import check_host_artifacts
from .editor import check_vscode
from .mechanism import check_ssh_authorized_keys, check_shell_profile, check_git_config_execution
from .remote import check_branch_protection
from stayawake.utils.render import SEVERITY, block, marked_list, paint

__all__ = [
    "HygieneIssue", "INCIDENT_TRIGGER_IDS", "ROTATION_UNSAFE_IDS", "rotation_safety",
    "incident_response_sequence",
    "check_credentials", "check_runner_persistence", "check_persistence",
    "check_persistence_coverage", "check_autorun", "check_host_artifacts",
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
        ("persistence surface readable", check_persistence_coverage),   # #1332 enumeration honesty
        ("host drop-files", lambda: check_host_artifacts(verify=verify_artifacts)),
        ("SSH authorized_keys", check_ssh_authorized_keys),
        ("shell startup files", check_shell_profile),
        ("git exec config", check_git_config_execution),
        ("autorun surface", check_autorun),                             # #1333 novel-foothold monitor
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


def _rotation_verdict(issues: list[HygieneIssue], *, color: bool, width: int) -> list[str]:
    """The run-level ROTATION-SAFETY verdict (#1332) — ALWAYS stated, reachable even with zero
    findings. Says explicitly whether credential rotation is safe, because rotating while a
    `gh-token-monitor` daemon is live arms a home-directory wiper. Three states (see models):
    SAFE (surface enumerated + clean), UNSAFE-persistence (a live foothold → the isolate/rotate-LAST
    runbook follows in _banner), UNSAFE-unknown (surface could not be read → treat as unsafe)."""
    verdict = rotation_safety({i.id for i in issues})
    if verdict == ROTATION_SAFE:
        return [paint("✓ Rotation safety: persistence surface enumerated and clean — rotating "
                      "credentials is safe.", SEVERITY["ok"], on=color)]
    if verdict == ROTATION_UNSAFE_PERSISTENCE:
        return [paint("⚠️  Rotation safety: UNSAFE — active host persistence detected; do NOT rotate "
                      "any credential yet (runbook below).", SEVERITY["warning"], on=color)]
    # UNSAFE-unknown: name exactly what could not be read, so the gap is actionable, not vague.
    lines = [paint("⚠️  Rotation safety: UNKNOWN — the persistence surface could not be fully "
                   "verified, so treat credential rotation as UNSAFE until it is.",
                   SEVERITY["warning"], on=color)]
    for i in issues:
        if i.severity == "unknown":
            lines += block(i.detail, indent=5, width=width)
    return lines


def render(issues: list[HygieneIssue], *, color: bool = False, width: int = 80) -> str:
    """Human-facing audit report. `color` (ANSI, gated by the caller via
    core.terminal.supports_color) and `width` (terminal columns, from core.render.term_width)
    default to plain/80 so a piped or test invocation is deterministic. Findings are grouped
    worst-first (warnings to act on, then weaker items to review); long detail/fix/runbook lines
    wrap to `width` with a hanging indent. The run-level rotation-safety verdict (#1332) always
    leads — reachable even when no individual finding is present."""
    rotation = _rotation_verdict(issues, color=color, width=width)

    # `unknown` items (unverified persistence surface) are surfaced in the rotation verdict above, not
    # as findings — they are the ABSENCE of a look, not something found. Split them out of the groups.
    warnings = [i for i in issues if i.severity == "warning"]
    reviews = [i for i in issues if i.severity == "info"]

    if not (warnings or reviews):
        # No findings. The verdict still stands: "clean" if the surface was verified, "unknown" if not.
        head = ("✓ Local security hygiene: no issues found."
                if all(i.severity != "unknown" for i in issues)
                else "Local security hygiene: no findings, but the persistence surface is UNVERIFIED.")
        code = SEVERITY["ok"] if "no issues" in head else SEVERITY["warning"]
        return "\n".join([paint(head, code, on=color), ""] + rotation).rstrip()

    counts = []
    if warnings:
        counts.append(f"{len(warnings)} warning{'' if len(warnings) == 1 else 's'}")
    if reviews:
        counts.append(f"{len(reviews)} to review")
    n = len(warnings) + len(reviews)
    lines = [f"Local security hygiene — {n} finding{'' if n == 1 else 's'}: " + ", ".join(counts), ""]
    lines += rotation + [""]

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
            if i.command:
                # The copy-pasteable command renders VERBATIM on its own line(s), never reflowed — a
                # wrapped command is unsafe to paste, and keeping it out of the prose makes it cleanly
                # selectable (#1237). Rationale stays in `remediation`; the deep "why" is the details link.
                lines += [f"       {cmd_line}" for cmd_line in i.command.split("\n")]
            if i.reference:
                lines.append("     " + paint("→ details: ", SEVERITY["info"], on=color) + i.reference)
            lines.append("")
    return "\n".join(lines).rstrip()
