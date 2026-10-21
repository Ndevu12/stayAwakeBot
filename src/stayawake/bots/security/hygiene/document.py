#!/usr/bin/env python3
"""The audit document a program reads. The same outcomes the report renders."""
from __future__ import annotations

from stayawake.bots.security.hygiene.models import (
    BLOCKED_ID, BLOCKED_SURFACE_ID, HygieneIssue, ROTATION_SAFE, ROTATION_SAFE_PENDING_CHECK,
    ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_STAGING, ROTATION_UNSAFE_UNKNOWN,
    SURFACE_UNREADABLE_ID, TIER_ACTIVE_PERSISTENCE, TIER_LEFT_OUTSIDE_A_CONTROL,
    VERIFY_BEFORE_ROTATE_IDS, display_rank, incident_tier, persistence_surface_is_enumerable,
    response_order, rotation_safety)
from stayawake.bots.security.hygiene.outcome import BLOCKED, CheckOutcome
from stayawake.bots.security.hygiene.process import live_process_scope_note
from stayawake.utils import docs_site, textsafe

_FIELD_LIMIT = 4000
_UNSAFE = {ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_STAGING, ROTATION_UNSAFE_UNKNOWN}
_BLOCKED_IDS = {BLOCKED_ID, BLOCKED_SURFACE_ID}


def shown(text: str) -> str:
    """Prepare one field the way the report prints it. Takes the text. Returns it."""
    out = textsafe.plain(text, limit=_FIELD_LIMIT)
    return out if len(out) < _FIELD_LIMIT else out + " […]"


def rotation_sentence(issues: list[HygieneIssue]) -> str:
    """State the rotation-safety sentence the report prints. Takes the issues. Returns it."""
    verdict = rotation_safety({i.id for i in issues})
    if verdict == ROTATION_SAFE_PENDING_CHECK:
        return ("Rotation safety: safe once you confirm the item(s) below are yours — "
                "if any is not, treat this as an incident and rotate LAST.")
    if verdict == ROTATION_SAFE:
        return ("Rotation safety: persistence surface enumerated and clean "
                "— rotating credentials is safe.")
    if verdict == ROTATION_UNSAFE_STAGING:
        what = ("a global resolution path was left outside a control"
                if incident_tier({i.id for i in issues}) == TIER_LEFT_OUTSIDE_A_CONTROL
                else "a staging artifact is in more than one place")
        return (f"Rotation safety: UNSAFE — {what}; inspect it before "
                "rotating any credential (note below).")
    if verdict == ROTATION_UNSAFE_PERSISTENCE:
        return ("Rotation safety: UNSAFE — active host persistence "
                "detected; do NOT rotate any credential yet (runbook below).")
    return ("Rotation safety: UNKNOWN — the persistence surface "
            "could not be established, so treat credential rotation as UNSAFE "
            "until it is.")


def finding_groups(issues: list[HygieneIssue]) -> tuple[list[HygieneIssue], list[HygieneIssue],
                                                       list[HygieneIssue]]:
    """List the findings the report shows. Takes the issues. Returns the critical, warning and
    review groups, each worst first."""
    def worst_first(items):
        return sorted(items, key=lambda i: (response_order(i.id), i.title))

    ranked = {id(i): display_rank(i.id, i.severity) for i in issues}
    return (
        worst_first(i for i in issues if ranked[id(i)] == "critical"),
        worst_first(i for i in issues if ranked[id(i)] == "warning"),
        worst_first(i for i in issues if i.severity == "info"),
    )


def scope_notes(issues: list[HygieneIssue]) -> list[str]:
    """State what the audit's result covers. Takes the issues. Returns each note, in report order."""
    ids = {i.id for i in issues}
    parts = []
    if not persistence_surface_is_enumerable():
        parts.append("start-up entries are not checked on this platform")
    elif ids & {SURFACE_UNREADABLE_ID, BLOCKED_SURFACE_ID}:
        parts.append("the start-up entries above were not all read")
    if incident_tier(ids) == TIER_ACTIVE_PERSISTENCE:
        parts.append("scope your response wider than this list")
    means = f" — {'; '.join(parts)}." if parts else "."
    notes = [f"Scope: this machine, not your online accounts. Not exhaustive{means} "
             f"{docs_site.WHAT_A_CLEAN_AUDIT_MEANS}"]
    processes = live_process_scope_note()
    if processes:
        notes.append(processes.capitalize() + ".")
    return notes


def _confidence(issue: HygieneIssue, rank: str) -> str:
    """Name the grade the report already gives a finding. Takes the finding and the rank it is
    shown at. Returns that grade."""
    if rank == "critical":
        return "confirmed"
    if issue.id in VERIFY_BEFORE_ROTATE_IDS:
        return "weak"
    return "heuristic"


def _finding(issue: HygieneIssue, rank: str) -> dict:
    """Describe one finding the report shows. Takes the finding and its rank. Returns it."""
    described = {
        "id": issue.id,
        "severity": rank,
        "title": shown(issue.title),
        "detail": shown(issue.detail),
        "fix": shown(issue.remediation),
    }
    if rank in ("critical", "warning", "info"):
        described["confidence"] = _confidence(issue, rank)
    if issue.command:
        described["command"] = issue.command
    if issue.reference:
        described["reference"] = issue.reference
    return described


def _verdict(issues: list[HygieneIssue], outcomes: list[CheckOutcome]) -> str:
    """Name the rotation verdict. Takes the issues and the probe outcomes. Returns `safe`,
    `safe-once-confirmed`, `unsafe` or `incomplete`."""
    safety = rotation_safety({i.id for i in issues})
    if safety in _UNSAFE:
        return "unsafe"
    if any(outcome.state == BLOCKED for outcome in outcomes):
        return "incomplete"
    if safety == ROTATION_SAFE_PENDING_CHECK:
        return "safe-once-confirmed"
    return "safe"


def as_document(outcomes: list[CheckOutcome]) -> dict:
    """Describe an audit for a program to read. Takes each probe's outcome. Returns the document,
    without its schema version."""
    issues = [issue for outcome in outcomes for issue in outcome.issues]
    criticals, warnings, reviews = finding_groups(issues)
    findings = ([_finding(issue, "critical") for issue in criticals]
                + [_finding(issue, "warning") for issue in warnings]
                + [_finding(issue, "info") for issue in reviews])
    grouped = {id(issue) for issue in (*criticals, *warnings, *reviews)}
    for issue in issues:
        if id(issue) in grouped or issue.id in _BLOCKED_IDS:
            continue
        findings.append(_finding(issue, issue.severity or "unknown"))
    incomplete = []
    for outcome in outcomes:
        if outcome.state != BLOCKED:
            continue
        for issue in outcome.issues:
            if issue.id not in _BLOCKED_IDS:
                continue
            incomplete.append({"probe": outcome.label, "reason": shown(issue.detail),
                               "title": shown(issue.title), "fix": shown(issue.remediation)})
    return {
        "rotation": {
            "verdict": _verdict(issues, outcomes),
            "sentence": rotation_sentence(issues),
            "to_confirm": [issue.id for issue in (*criticals, *warnings, *reviews)
                           if issue.id in VERIFY_BEFORE_ROTATE_IDS],
        },
        "findings": findings,
        "incomplete": incomplete,
        "scope_notes": scope_notes(issues),
    }
