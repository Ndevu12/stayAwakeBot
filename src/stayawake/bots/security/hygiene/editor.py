#!/usr/bin/env python3
"""Editor (VS Code) hygiene — folder-open auto-run tasks + Workspace Trust (the auto-run vector)."""
from __future__ import annotations

import os
import re
from pathlib import Path

from stayawake.utils.pathsafe import grade

from .models import HygieneIssue, could_not_read


_DOCS = ("https://github.com/Ndevu12/stayAwakeBot/blob/main/docs/how-to/audit-a-machine.md"
         "#what-a-clean-audit-does-and-does-not-mean")


def _vscode_user_settings() -> tuple[Path | None, bool]:
    home = Path.home()
    candidates = [
        home / "Library/Application Support/Code/User/settings.json",
        home / ".config/Code/User/settings.json",
        Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Code/User/settings.json",
    ]
    for c in candidates:
        state = grade(c)
        if state == "absent":
            continue
        if state == "unverified":
            return c, True
        return c, False
    return None, False


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


def check_vscode(settings_path: Path | None = None) -> list[HygieneIssue]:
    issues: list[HygieneIssue] = []
    if settings_path is not None:
        path, unread = settings_path, grade(settings_path) == "unverified"
    else:
        path, unread = _vscode_user_settings()
    if unread:
        return [could_not_read([path])]
    if path is None:
        return issues
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return [could_not_read([path])]

    auto = re.search(r'"task\.allowAutomaticTasks"\s*:\s*"([^"]+)"', text)
    if auto is None:
        issues.append(HygieneIssue(
            id="vscode-autotasks-default",
            severity="info",
            title="VS Code automatic tasks not explicitly disabled",
            detail=f'{path} does not set "task.allowAutomaticTasks", so a folder can auto-run tasks '
                   "when opened.",
            remediation='Set "task.allowAutomaticTasks": "off".', reference=_DOCS,
        ))
    elif auto.group(1) != "off":
        issues.append(HygieneIssue(
            id="vscode-autotasks-on",
            severity="warning",
            title="VS Code automatic tasks are enabled",
            detail=f'{path} sets "task.allowAutomaticTasks": "{auto.group(1)}" — folder-open '
                   "tasks can run on open without confirmation.",
            remediation='Set "task.allowAutomaticTasks": "off".',
        ))

    if re.search(r'"security\.workspace\.trust\.enabled"\s*:\s*false', text):
        issues.append(HygieneIssue(
            id="vscode-workspace-trust-off",
            severity="warning",
            title="VS Code Workspace Trust is disabled",
            detail=f"{path} disables Workspace Trust, so untrusted folders run code freely.",
            remediation='Set "security.workspace.trust.enabled": true.', reference=_DOCS,
        ))

    if re.search(r'"security\.workspace\.trust\.untrustedFiles"\s*:\s*"open"', text):
        issues.append(HygieneIssue(
            id="vscode-untrusted-files-open",
            severity="warning",
            title="VS Code opens untrusted files without prompting",
            detail=f'{path} sets "security.workspace.trust.untrustedFiles": "open", so untrusted '
                   "files open without the trust prompt.",
            remediation='Set it to "prompt" (the default).', reference=_DOCS,
        ))

    if _autoapprove_approves_everything(text):
        issues.append(HygieneIssue(
            id="vscode-autoapprove-all",
            severity="warning",
            title="VS Code auto-approves ALL terminal commands for chat/agent tools",
            detail=f'{path} auto-approves EVERY terminal command via '
                   '"chat.tools.terminal.autoApprove", so anything an AI agent proposes runs '
                   "unprompted.",
            remediation='Replace the blanket/catch-all with an explicit allowlist object of safe '
                        "commands (or set it to false); never auto-approve everything.",
        ))
    else:
        risky = risky_autoapprove_entries(text)
        if risky:
            issues.append(HygieneIssue(
                id="vscode-autoapprove-risky",
                severity="warning",
                title="VS Code auto-approves risky terminal commands for chat/agent tools",
                detail=f'{path} auto-approves {", ".join(risky)} via '
                       '"chat.tools.terminal.autoApprove", so an AI agent runs them unprompted.',
                remediation='Remove those entries, or set them to false.', reference=_DOCS,
            ))
    return issues
