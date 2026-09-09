#!/usr/bin/env python3
"""Editor hygiene — folder-open auto-run tasks + Workspace Trust (the auto-run vector).

Every editor of the VS Code family on this machine, not whichever one was found first. They share
the settings schema, so one set of checks covers them; `editors.py` decides which are here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils.pathsafe import grade

from . import editors
from .models import HygieneIssue, could_not_read


_DOCS = ("https://github.com/Ndevu12/stayAwakeBot/blob/main/docs/how-to/audit-a-machine.md"
         "#what-a-clean-audit-does-and-does-not-mean")


@dataclass(frozen=True)
class Setting:
    """One editor setting this tool grades, and how it is answered.

    `correct` is the one literal that answers it. `turns_off_entries` marks the other shape: a
    table of commands, answered by turning the dangerous ones off rather than by one value.
    """

    key: str
    correct: str | None
    turns_off_entries: bool = False


_AUTOTASKS = Setting("task.allowAutomaticTasks", '"off"')
_TRUST_ENABLED = Setting("security.workspace.trust.enabled", "true")
_UNTRUSTED_FILES = Setting("security.workspace.trust.untrustedFiles", '"prompt"')
AUTO_APPROVE = Setting("chat.tools.terminal.autoApprove", None, turns_off_entries=True)

SETTING_FOR = {
    "editor-autotasks-default": _AUTOTASKS,
    "editor-autotasks-on": _AUTOTASKS,
    "editor-workspace-trust-off": _TRUST_ENABLED,
    "editor-untrusted-files-open": _UNTRUSTED_FILES,
    "editor-autoapprove-all": AUTO_APPROVE,
    "editor-autoapprove-risky": AUTO_APPROVE,
}

EDITORS_NOT_EXAMINED_ID = "editors-not-examined"


_RISKY_AUTOAPPROVE = ("npx", "npm", "pnpm", "yarn", "node", "ssh", "scp", "curl", "wget",
                      "bash", "sh", "zsh", "eval", "sed", "awk", "python", "python3", "rm")

_CATCHALL_REGEX_BODIES = {"", ".", ".*", ".+", "^", "$", "^$", "^.*$", "^.*", ".*$", "^.+$", "^.+", ".+$"}


def _autoapprove_is_blanket_true(text: str) -> bool:
    """True for `"chat.tools.terminal.autoApprove": true` — approve EVERY terminal command, the single
    most dangerous form (and the one a naive `:\\s*\\{` object probe misses entirely)."""
    return re.search(r'"chat\.tools\.terminal\.autoApprove"\s*:\s*true\b', text) is not None


def _autoapprove_block(text: str) -> str | None:
    """The `chat.tools.terminal.autoApprove` OBJECT value, extracted by BALANCED braces so a nested
    object rule (`"npx": { "approve": true }`) doesn't truncate the scan at its first `}` — a plain
    `.*?` regex drops every sibling after the first object-valued key. String-AWARE so a brace inside a
    quoted key (`"rm {": true`, a valid regex/prefix) doesn't unbalance the count. None if the key is
    absent or its value isn't an object."""
    m = re.search(r'"chat\.tools\.terminal\.autoApprove"\s*:\s*', text)
    if m is None or m.end() >= len(text) or text[m.end()] != "{":
        return None
    depth, in_str, esc = 0, False, False
    for j in range(m.end(), len(text)):
        c = text[j]
        if in_str:                          # ignore everything (incl. braces) inside a JSON string
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[m.end():j + 1]
    return None


def _autoapprove_approves_everything(text: str) -> bool:
    """True when autoApprove effectively approves ALL commands — either the blanket `: true`, or a
    catch-all REGEX key (`"/.*/": true`, `"/^/": {"approve": true}`) that matches every command line."""
    if _autoapprove_is_blanket_true(text):
        return True
    block = _autoapprove_block(text)
    if block is None:
        return False
    for m in re.finditer(r'"(/[^"]*/)"\s*:\s*(?:true\b|\{[^{}]*"approve"\s*:\s*true)', block):
        if m.group(1)[1:-1] in _CATCHALL_REGEX_BODIES:      # strip the surrounding /…/
            return True
    return False


def catchall_autoapprove_entries(text: str) -> list[str]:
    """The regex keys under `autoApprove` that match every command line, approved.

    Named rather than counted, so the caller turns off the entries the check actually found.
    """
    block = _autoapprove_block(text)
    if block is None:
        return []
    found: list[str] = []
    for m in re.finditer(r'"(/[^"]*/)"\s*:\s*(?:true\b|\{[^{}]*"approve"\s*:\s*true)', block):
        if m.group(1)[1:-1] in _CATCHALL_REGEX_BODIES and m.group(1) not in found:
            found.append(m.group(1))
    return found


def blanket_autoapprove(text: str) -> bool:
    """Whether `autoApprove` is the single value `true` — approve every terminal command."""
    return _autoapprove_is_blanket_true(text)


def risky_autoapprove_entries(text: str) -> list[str]:
    """Best-effort: risky command names auto-approved via `chat.tools.terminal.autoApprove`. Flags a
    key CONTAINING a risky name that is approved either directly (`"npx": true`) or via the object form
    (`"npx": { "approve": true }`). A name set to `false` (a deny) is NOT flagged."""
    block = _autoapprove_block(text)
    if block is None:
        return []
    found: list[str] = []
    for name in _RISKY_AUTOAPPROVE:
        esc = re.escape(name)
        direct = rf'"[^"]*\b{esc}\b[^"]*"\s*:\s*true\b'
        obj = rf'"[^"]*\b{esc}\b[^"]*"\s*:\s*\{{[^{{}}]*"approve"\s*:\s*true'
        if (re.search(direct, block) or re.search(obj, block)) and name not in found:
            found.append(name)
    return found


def grade_settings(text: str, name: str, path: Path) -> list[HygieneIssue]:
    """Grade one editor's settings text. Returns a finding for each answer it does not hold."""
    issues: list[HygieneIssue] = []
    auto = re.search(r'"task\.allowAutomaticTasks"\s*:\s*"([^"]+)"', text)
    if auto is None:
        issues.append(HygieneIssue(
            id="editor-autotasks-default",
            severity="info",
            title=f"{name} automatic tasks are not explicitly disabled",
            detail="A folder can auto-run tasks when it is opened.",
            remediation="Run `saw harden`.", reference=_DOCS,
        ))
    elif auto.group(1) != "off":
        issues.append(HygieneIssue(
            id="editor-autotasks-on",
            severity="warning",
            title=f"{name} automatic tasks are enabled",
            detail="Folder-open tasks run without confirmation.",
            remediation="Run `saw harden`.", reference=_DOCS,
        ))

    if re.search(r'"security\.workspace\.trust\.enabled"\s*:\s*false', text):
        issues.append(HygieneIssue(
            id="editor-workspace-trust-off",
            severity="warning",
            title=f"{name} Workspace Trust is disabled",
            detail="Untrusted folders run code freely.",
            remediation="Run `saw harden`.", reference=_DOCS,
        ))

    if re.search(r'"security\.workspace\.trust\.untrustedFiles"\s*:\s*"open"', text):
        issues.append(HygieneIssue(
            id="editor-untrusted-files-open",
            severity="warning",
            title=f"{name} opens untrusted files without prompting",
            detail="Untrusted files open without the trust prompt.",
            remediation="Run `saw harden`.", reference=_DOCS,
        ))

    if _autoapprove_approves_everything(text):
        issues.append(HygieneIssue(
            id="editor-autoapprove-all",
            severity="warning",
            title=f"{name} auto-approves ALL terminal commands for chat/agent tools",
            detail="Anything an AI agent proposes runs unprompted.",
            remediation="Run `saw harden`.",
        ))
    else:
        risky = risky_autoapprove_entries(text)
        if risky:
            issues.append(HygieneIssue(
                id="editor-autoapprove-risky",
                severity="warning",
                title=f"{name} auto-approves risky terminal commands for chat/agent tools",
                detail=f"An AI agent runs {', '.join(risky)} unprompted.",
                remediation="Run `saw harden`.", reference=_DOCS,
            ))
    return issues


def check_editors(settings_path: Path | None = None, find=editors.installed) -> list[HygieneIssue]:
    """Grade every editor of this family on this machine.

    Takes one settings file to grade instead, which is how a test names what it acts on.
    """
    if settings_path is not None:
        found = editors.Found([editors.Editor("This editor", settings_path)], [], [])
    else:
        found = find()
    issues: list[HygieneIssue] = []
    unread: list[Path] = list(found.unreadable)
    for editor in found.editors:
        if grade(editor.settings) == "unverified":
            unread.append(editor.settings)
            continue
        try:
            text = editor.settings.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            unread.append(editor.settings)
            continue
        issues += grade_settings(text, editor.name, editor.settings)
    if unread:
        issues.append(could_not_read(unread))
    if found.not_modelled:
        issues.append(HygieneIssue(
            id=EDITORS_NOT_EXAMINED_ID,
            severity="unknown",
            title="An editor on this machine was not examined",
            detail="An editor here is not modelled, so no result covers it.",
            remediation="Check its auto-run and trust settings yourself.", reference=_DOCS,
        ))
    return issues
