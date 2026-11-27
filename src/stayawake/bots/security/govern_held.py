#!/usr/bin/env python3
"""What `saw govern` tells the user about an update it held."""
from __future__ import annotations

import os
from pathlib import Path

from stayawake.bots.security.models import CONFIRMED, INFECTED, SUSPICIOUS, Finding, ScanResult

LET_IN = "let-in"
LET_IN_CHOICES = (LET_IN, "leave-unchanged")
CONFIRM_YES = "yes"
CONFIRM_TYPED = "typed"
HELD_VERDICTS = (SUSPICIOUS, INFECTED)
RECORDED_FINDING_FIELDS = ("signature_id", "severity", "path", "description")


def _key(finding: Finding) -> tuple[str, str, str]:
    return finding.signature_id, finding.path, finding.evidence or ""


def set_aside_already_there(update: ScanResult, before: ScanResult) -> list[Finding]:
    """Set aside the update's findings the folder already had. Takes the update's result and the
    same files' result before the update. Returns the findings set aside."""
    earlier = {_key(finding) for finding in before.findings}
    kept, already = [], []
    for finding in update.findings:
        if finding.confidence != CONFIRMED and _key(finding) in earlier:
            already.append(finding)
        else:
            kept.append(finding)
    update.findings = kept
    return already


def details(answer: dict, command: list[str], folder: str, let_in: bool) -> dict:
    """Gather what the terminal shows about a held update, for the status record. Takes prepare's
    answer, the command line with the tool first, the folder it ran in and whether `saw govern
    let-in` reviews this update. Returns the findings with the scan document's field names, the
    command, the next steps and `let_in`."""
    findings = (((answer.get("scan") or {}).get("results") or [{}])[0] or {}).get("findings") or []
    return {"findings": [{field: finding.get(field) for field in RECORDED_FINDING_FIELDS}
                         for finding in findings if isinstance(finding, dict)],
            "command": {"argv": list(command), "folder": folder},
            "next_steps": [step for step in answer.get("next_steps") or [] if isinstance(step, str)],
            "let_in": let_in}


def folder_name(repo: str) -> str:
    """Return the open folder's name. Takes the open folder."""
    return Path(os.path.abspath(repo)).name


def decision(repo: str, into: str, commit: str, verdict: str) -> dict:
    """Build the way through for a held update. Takes the open folder, the holding directory, the
    checked commit and the verdict. Returns the choices, the let-in command and the confirmation."""
    body = {"choices": list(LET_IN_CHOICES),
            "let_in": ["saw", "govern", "apply", "--repo", str(repo), "--into", str(into),
                       "--accept", commit],
            "confirm": CONFIRM_TYPED if verdict == INFECTED else CONFIRM_YES}
    if verdict == INFECTED:
        body["type_to_confirm"] = folder_name(repo)
    return body


def next_steps(verdict: str, findings: list[dict], already_there: list[dict], commit: str, *,
               can_let_in: bool = True) -> list[str]:
    """Write what the user should do about a held update. Takes the verdict, the update's
    findings, the ones already in the folder, the checked commit and whether saw can let it in.
    Returns the steps."""
    steps: list[str] = []
    short = commit[:12]
    if verdict == INFECTED:
        steps += [f"Do not merge, check out or run anything from {short}."] if short else []
        steps += ["Tell whoever pushed it: their account or machine may be compromised.",
                  "If it is already in your own branches, run `saw fix`, then `saw fix amend`.",
                  "Before you change any password, run `saw audit`."]
    elif verdict == SUSPICIOUS:
        for finding in findings:
            steps.append(f"Check {finding.get('path')}: {finding.get('description')}. "
                         "Make sure it is yours.")
        if can_let_in:
            steps.append(f"If it is, let {short} in; saw applies exactly the update it checked.")
    for finding in already_there:
        steps.append(f"The update changes {finding.get('path')}; this was already there before it: "
                     f"{finding.get('description')}")
    return steps
