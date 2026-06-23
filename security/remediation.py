#!/usr/bin/env python3
"""Remediation engine — turn findings into safe, reversible changes.

Each finding carries a `remediation` id (from the signature DB); this module maps
ids to concrete `Change`s and applies them. Every applied change first backs the
original up to a quarantine directory (reversible). Pure planning is separate from
side-effecting apply so dry-run is trivial.
"""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from security.matchers.base import load_jsonc

# remediation id → internal action
_ACTIONS = {
    "strip-appended-payload": "strip-payload",
    "quarantine-file": "quarantine",
    "quarantine-dir": "quarantine",
    "remove-foreign-vscode": "vscode",
    "strip-gitignore-markers": "strip-gitignore",
}
_GITIGNORE_MARKERS = {"branch_structure.json", "temp_auto_push.bat", "temp_interactive_push.bat"}


@dataclass(frozen=True)
class Change:
    action: str        # strip-payload | quarantine | strip-gitignore | strip-settings
    path: str          # repo-relative path the action targets
    detail: str = ""


def _fonts_dir(rel: str) -> str:
    """Map a path inside a camouflage fonts dir to that directory."""
    parts = rel.split("/")
    if "fonts" in parts:
        i = len(parts) - 1 - parts[::-1].index("fonts")
        return "/".join(parts[: i + 1])
    return str(Path(rel).parent)


def plan(findings) -> list[Change]:
    """Map findings to a deduped list of changes (pure — no filesystem access)."""
    changes: dict[tuple[str, str], Change] = {}
    for f in findings:
        action = _ACTIONS.get(getattr(f, "remediation", "manual"))
        if action is None:
            continue                      # manual (e.g. evil-merge) — not auto-fixed
        path = f.path
        if f.remediation == "quarantine-dir":
            path = _fonts_dir(f.path)
        if action == "vscode":
            if f.path.endswith("tasks.json"):
                c = Change("quarantine", f.path, "VS Code auto-run task harness")
            elif f.path.endswith("settings.json"):
                c = Change("strip-settings", f.path, "remove allowAutomaticTasks/tasks")
            else:
                continue
        else:
            c = Change(action, path, f.description[:60])
        changes[(c.action, c.path)] = c
    return list(changes.values())


# ── individual transforms ────────────────────────────────────────────────────

def strip_payload_text(text: str) -> str:
    """Keep the legit config up to the first `export default ...;`; drop the
    appended payload and any injected createRequire preamble."""
    out: list[str] = []
    for line in text.splitlines():
        if line.lstrip().startswith("import { createRequire }") or "createRequire(" in line:
            continue
        if "export default" in line:
            idx = line.find(";")
            out.append(line[: idx + 1] if idx != -1 else line)
            return "\n".join(out).rstrip("\n") + "\n"
        out.append(line)
    return "\n".join(out).rstrip("\n") + "\n"


def strip_gitignore_text(text: str) -> str:
    return "\n".join(l for l in text.splitlines()
                     if l.strip() not in _GITIGNORE_MARKERS).rstrip("\n") + "\n"


def strip_settings_autorun(text: str) -> str:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        return text
    data.pop("task.allowAutomaticTasks", None)
    data.pop("tasks", None)
    return json.dumps(data, indent=2) + "\n"


def _backup(root: Path, rel: str, quarantine: Path) -> None:
    src = root / rel
    if not src.exists():
        return
    dest = quarantine / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dest)


def apply(root: Path, changes: list[Change], quarantine: Path) -> list[Change]:
    """Apply changes in-place under `root`, backing up originals to `quarantine`.

    Idempotent: a change whose target is already gone/clean is skipped.
    """
    applied: list[Change] = []
    for c in changes:
        target = root / c.path
        if c.action == "quarantine":
            if target.exists():
                _backup(root, c.path, quarantine)
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
                applied.append(c)
        elif c.action in ("strip-payload", "strip-gitignore", "strip-settings"):
            if not target.exists():
                continue
            original = target.read_text(encoding="utf-8", errors="replace")
            if c.action == "strip-payload":
                new = strip_payload_text(original)
            elif c.action == "strip-gitignore":
                new = strip_gitignore_text(original)
            else:
                new = strip_settings_autorun(original)
            if new != original:
                _backup(root, c.path, quarantine)
                target.write_text(new, encoding="utf-8")
                applied.append(c)
    return applied
