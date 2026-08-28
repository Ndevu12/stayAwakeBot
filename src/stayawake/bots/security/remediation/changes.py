#!/usr/bin/env python3
"""Map findings to structure-safe changes and apply them."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.matchers.base import load_jsonc
from stayawake.bots.security.models import CONFIRMED, QUARANTINE_DIR

_ACTIONS = {
    "quarantine-file": "quarantine",
    "quarantine-dir": "quarantine",
    "remove-foreign-vscode": "vscode",
    "strip-gitignore-markers": "strip-gitignore",
}
_GITIGNORE_MARKERS = {"branch_structure.json", "temp_auto_push.bat", "temp_interactive_push.bat"}

_QUARANTINE_COMMENT = "# Malware quarantine / remediation artifacts (kept local, never committed)"
_QUARANTINE_PATTERNS = (QUARANTINE_DIR + "/",)


def is_auto_fixable(finding) -> bool:
    """True when a confirmed finding has a known automatic remediation."""
    if getattr(finding, "confidence", None) != CONFIRMED:
        return False
    return getattr(finding, "remediation", "manual") in _ACTIONS


def quarantine_path(root: Path) -> Path:
    return root / QUARANTINE_DIR


@dataclass(frozen=True)
class Change:
    action: str
    path: str
    detail: str = ""


def _fonts_dir(rel: str) -> str:
    """Map a path inside a camouflage fonts dir to that directory."""
    parts = rel.split("/")
    if "fonts" in parts:
        i = len(parts) - 1 - parts[::-1].index("fonts")
        return "/".join(parts[: i + 1])
    parent = str(Path(rel).parent)
    return rel if parent in (".", "") else parent


def plan(findings) -> list[Change]:
    """Map findings to a deduped list of changes (pure — no filesystem access)."""
    changes: dict[tuple[str, str], Change] = {}
    for f in findings:
        if not is_auto_fixable(f):
            continue
        action = _ACTIONS[getattr(f, "remediation", "manual")]
        path = f.path
        if f.remediation == "quarantine-dir":
            path = _fonts_dir(f.path)
        if not path or Path(path) in (Path("."), Path("..")):
            continue
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


def ensure_ignored(root: Path) -> bool:
    """Append quarantine ignore patterns to `root/.gitignore`. True if the file changed."""
    gi = root / ".gitignore"
    if gi.is_symlink():
        return False
    text = gi.read_text(encoding="utf-8", errors="replace") if gi.exists() else ""
    present = {l.strip() for l in text.splitlines()}
    missing = [p for p in _QUARANTINE_PATTERNS if p not in present]
    if not missing:
        return False
    block: list[str] = []
    if _QUARANTINE_COMMENT not in present:
        block.append(_QUARANTINE_COMMENT)
    block += missing
    head = (text.rstrip("\n") + "\n\n") if text.strip() else ""
    gi.write_text(head + "\n".join(block) + "\n", encoding="utf-8")
    return True


def _dest_ready(quarantine: Path, dest: Path) -> bool:
    try:
        if dest.is_symlink() or dest.exists():
            return False
        try:
            lexical = dest.relative_to(quarantine)
        except ValueError:
            return False
        if lexical == Path(".") or ".." in lexical.parts:
            return False
        q = quarantine.resolve()
        resolved = dest.resolve()
        if resolved == q or not resolved.is_relative_to(q):
            return False
        p = dest.parent
        while True:
            if p.is_symlink():
                return False
            pr = p.resolve()
            if not pr.is_relative_to(q):
                return False
            if pr == q:
                return True
            if p.parent == p:
                return False
            p = p.parent
    except (OSError, RuntimeError, ValueError):
        return False


def _backup(root: Path, rel: str, quarantine: Path) -> None:
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        return
    src = root / rel
    if not src.exists():
        return
    if src.is_symlink():
        return
    dest = quarantine / rel
    if not _dest_ready(quarantine, dest):
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not _dest_ready(quarantine, dest):
        return
    if src.is_dir():
        shutil.copytree(src, dest, symlinks=True)
    else:
        shutil.copy2(src, dest, follow_symlinks=False)


def _delete_stays_in(root: Path, target: Path) -> bool:
    try:
        base = root.resolve()
        if target.is_symlink():
            return target.parent.resolve().is_relative_to(base)
        if not is_safe_write_target(target, root):
            return False
        return target.resolve() != base
    except (OSError, RuntimeError, ValueError):
        return False


def quarantine_residual(root: Path, findings, quarantine: Path) -> list["Change"]:
    """Back up and remove each remaining flagged path."""
    done: list[Change] = []
    for rel in sorted({f.path for f in findings}):
        target = root / rel
        if not target.exists() or not _delete_stays_in(root, target):
            continue
        _backup(root, rel, quarantine)
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
        done.append(Change("quarantine", rel, "residual after remediation"))
    return done


def apply(root: Path, changes: list[Change], quarantine: Path) -> list[Change]:
    """Apply changes in-place under `root`, backing up originals to `quarantine`.

    Idempotent: a change whose target is already gone/clean is skipped.
    """
    applied: list[Change] = []
    for c in changes:
        target = root / c.path
        if c.action == "quarantine":
            if target.exists() and _delete_stays_in(root, target):
                _backup(root, c.path, quarantine)
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink()
                applied.append(c)
        elif c.action in ("strip-gitignore", "strip-settings"):
            if not target.exists():
                continue
            if not is_safe_write_target(target, root):
                continue
            try:
                if target.stat().st_nlink > 1:
                    continue
            except OSError:
                continue
            original = target.read_text(encoding="utf-8", errors="replace")
            if c.action == "strip-gitignore":
                new = strip_gitignore_text(original)
            else:
                new = strip_settings_autorun(original)
            if new != original:
                _backup(root, c.path, quarantine)
                target.write_text(new, encoding="utf-8")
                applied.append(c)
    return applied
