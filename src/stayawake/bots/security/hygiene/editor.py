#!/usr/bin/env python3
"""Editor (VS Code) hygiene — folder-open auto-run tasks + Workspace Trust (the auto-run vector)."""
from __future__ import annotations

import os
import re
from pathlib import Path

from .models import HygieneIssue


def _vscode_user_settings() -> Path | None:
    """Locate the VS Code user settings.json across macOS / Linux / Windows."""
    home = Path.home()
    candidates = [
        home / "Library/Application Support/Code/User/settings.json",   # macOS
        home / ".config/Code/User/settings.json",                       # Linux
        Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Code/User/settings.json",  # Windows
    ]
    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def check_vscode(settings_path: Path | None = None) -> list[HygieneIssue]:
    issues: list[HygieneIssue] = []
    path = settings_path if settings_path is not None else _vscode_user_settings()
    if path is None:
        return issues  # VS Code not detected — nothing to assert
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return issues

    # JSONC-tolerant key probes (settings.json allows comments / trailing commas).
    auto = re.search(r'"task\.allowAutomaticTasks"\s*:\s*"([^"]+)"', text)
    if auto is None:
        issues.append(HygieneIssue(
            id="vscode-autotasks-default",
            severity="info",
            title="VS Code automatic tasks not explicitly disabled",
            detail=f'{path} does not set "task.allowAutomaticTasks". Folder-open auto-run is '
                   "the vector the worm used to execute a disguised font on open.",
            remediation='Set "task.allowAutomaticTasks": "off" in VS Code user settings.',
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
            remediation='Remove the override or set "security.workspace.trust.enabled": true.',
        ))
    return issues


