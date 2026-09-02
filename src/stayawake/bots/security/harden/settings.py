#!/usr/bin/env python3
"""Correct an editor setting that lets a folder run code without being asked.

These are the safest changes this tool can make: one file, owned by the person running the
command, and a value the audit already prints. `saw audit` has been printing the correct value
and changing nothing, which leaves the work — and the risk of doing it by hand at speed, during
an incident — with them.

What is corrected is deliberately narrow. A setting whose remediation offers a CHOICE has no
known-correct value, so it stays reported: this writes values, it does not make decisions. No key
is ever removed, and no entry is ever added, because neither can be put back by an undo that only
restores what it saved.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.bots.security.harden import jsonc
from stayawake.bots.security.hygiene.editor import risky_autoapprove_entries


@dataclass(frozen=True)
class Correction:
    """One finding this can answer, and the value it would write."""

    issue_id: str
    key: str
    value: str


@dataclass(frozen=True)
class Planned:
    """A correction with the exact edit it would make, before anything is written."""

    issue_id: str
    edit: jsonc.Edit

    def described(self) -> str:
        if self.edit.adds:
            return f'  add     "{self.edit.key}": {self.edit.value}'
        return f'  change  "{self.edit.key}": {self.edit.was} -> {self.edit.value}'


@dataclass(frozen=True)
class Skipped:
    """A finding this will not answer, and why — never silently dropped."""

    issue_id: str
    reason: str


_CORRECTIONS = (
    Correction("vscode-autotasks-default", "task.allowAutomaticTasks", '"off"'),
    Correction("vscode-autotasks-on", "task.allowAutomaticTasks", '"off"'),
    Correction("vscode-workspace-trust-off", "security.workspace.trust.enabled", "true"),
    Correction("vscode-untrusted-files-open",
               "security.workspace.trust.untrustedFiles", '"prompt"'),
)
_CORRECTION_BY_ID = {c.issue_id: c for c in _CORRECTIONS}

_AUTOAPPROVE = "chat.tools.terminal.autoApprove"
_RISKY_ID = "vscode-autoapprove-risky"

_WHY_NOT_WRITTEN = {
    "vscode-autoapprove-all":
        "its own remediation offers a choice between an allowlist and turning it off, so there is "
        "no single correct value to write",
}


def plan(text: str, issue_ids) -> tuple[str, list[Planned], list[Skipped]]:
    """Every edit the findings in `issue_ids` ask for, applied to a copy of `text`.

    Returns the corrected text alongside what was planned and what was not. Nothing is written
    here: the caller shows this to a person first.
    """
    planned: list[Planned] = []
    skipped: list[Skipped] = []
    for issue_id in sorted(issue_ids):
        if issue_id == _RISKY_ID:
            text, done, missed = _plan_entries(text)
            planned += done
            skipped += missed
            continue
        if issue_id in _WHY_NOT_WRITTEN:
            skipped.append(Skipped(issue_id, _WHY_NOT_WRITTEN[issue_id]))
            continue
        correction = _CORRECTION_BY_ID.get(issue_id)
        if correction is None:
            continue
        if jsonc.value_at(text, correction.key) == correction.value:
            skipped.append(Skipped(issue_id, "already set to that value when it was read"))
            continue
        result = jsonc.set_value(text, correction.key, correction.value)
        if result is None:
            skipped.append(Skipped(issue_id, f'"{correction.key}" is not somewhere this can '
                                             "write to without guessing"))
            continue
        text, edit = result
        planned.append(Planned(issue_id, edit))
    return text, planned, skipped


def _plan_entries(text: str) -> tuple[str, list[Planned], list[Skipped]]:
    """Turn off each auto-approved command the check names, one entry at a time.

    The check is asked which entries those are rather than the finding's sentence being read back
    — the sentence is a rendering of the answer, not the answer.
    """
    named = risky_autoapprove_entries(text)
    if not named:
        return text, [], [Skipped(_RISKY_ID, "no auto-approved command was named when it was read")]
    planned: list[Planned] = []
    skipped: list[Skipped] = []
    for entry in named:
        result = jsonc.set_member(text, _AUTOAPPROVE, entry, "false")
        if result is None:
            skipped.append(Skipped(_RISKY_ID, f'"{entry}" is not somewhere this can write to '
                                              "without guessing"))
            continue
        text, edit = result
        planned.append(Planned(_RISKY_ID, edit))
    return text, planned, skipped


def answerable(issue_ids) -> set[str]:
    """The findings this knows a correct value for. Everything else stays reported."""
    return {i for i in issue_ids if i in _CORRECTION_BY_ID or i == _RISKY_ID}


def reported_only(issue_ids) -> set[str]:
    """Findings this could reach and deliberately does not write."""
    return {i for i in issue_ids if i in _WHY_NOT_WRITTEN}


def diff(before: str, after: str, path: Path) -> str:
    """The change, as the person running this will see it before agreeing to it."""
    import difflib
    lines = difflib.unified_diff(before.splitlines(keepends=True),
                                 after.splitlines(keepends=True),
                                 fromfile=str(path), tofile=f"{path} (proposed)")
    return "".join(lines).rstrip()
