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

from stayawake.bots.security.matchers.base import load_jsonc
from stayawake.bots.security.models import QUARANTINE_DIR

# remediation id → internal action
_ACTIONS = {
    "strip-appended-payload": "strip-payload",
    "quarantine-file": "quarantine",
    "quarantine-dir": "quarantine",
    "remove-foreign-vscode": "vscode",
    "strip-gitignore-markers": "strip-gitignore",
}
_GITIGNORE_MARKERS = {"branch_structure.json", "temp_auto_push.bat", "temp_interactive_push.bat"}

# Loader fingerprints (mirror the content signatures) used to drop payload lines
# wherever they sit — not only when appended after `export default`.
_LOADER_LINE = re.compile(
    r"createRequire\(|String\s*[.\[]\s*['\"]?fromCharCode['\"]?\]?\s*\(\s*(?:127|0x7f)"
    r"|(?:var|let|const)\s+_\$_[0-9a-f]{2,}\s*=|=\s*sfL\(|global\s*\[\s*(?:_\$_|['\"]!['\"])",
    re.IGNORECASE,
)

# Quarantine / remediation backups must stay local and never be committed.
# `ensure_ignored` guarantees a target repo's .gitignore carries this before we
# `git add` a fix, so backups never leak into a commit or PR.
_QUARANTINE_COMMENT = "# Malware quarantine / remediation artifacts (kept local, never committed)"
_QUARANTINE_PATTERNS = (QUARANTINE_DIR + "/",)


def is_auto_fixable(finding) -> bool:
    """True if a finding has a known automatic remediation (i.e. not `manual`)."""
    return getattr(finding, "remediation", "manual") in _ACTIONS


def quarantine_path(root: Path) -> Path:
    return root / QUARANTINE_DIR


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
    """Remove worm loader lines wherever they sit (not only appended after the
    config) and cut any payload appended past the first `export default ...;`.

    Best-effort: a post-apply re-scan (see `verify_clean`) is the real guarantee —
    if any signature still fires the caller quarantines the whole file."""
    out: list[str] = []
    for line in text.splitlines():
        if _LOADER_LINE.search(line):
            continue                      # drop loader / createRequire lines at any position
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


def ensure_ignored(root: Path) -> bool:
    """Guarantee `root/.gitignore` ignores quarantine/remediation artifacts.

    Appends any missing patterns (and the explanatory comment) idempotently.
    Returns True if the file was changed. Called before `git add` so backups
    never land in a commit or PR.
    """
    gi = root / ".gitignore"
    if gi.is_symlink():
        return False                      # refuse to follow a symlinked .gitignore (write-through guard)
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


def _backup(root: Path, rel: str, quarantine: Path) -> None:
    src = root / rel
    if not src.exists():
        return
    if src.is_symlink():
        return                            # never dereference a symlinked target into quarantine
    dest = quarantine / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        # symlinks=True recreates inner symlinks as links instead of copying their
        # (possibly out-of-tree) targets' contents into the quarantine.
        shutil.copytree(src, dest, dirs_exist_ok=True, symlinks=True)
    else:
        shutil.copy2(src, dest, follow_symlinks=False)


def quarantine_residual(root: Path, findings, quarantine: Path) -> list["Change"]:
    """Quarantine (back up + remove) every distinct file still flagged after a
    strip/apply pass — the fail-safe so a partially-cleaned file is never left behind.
    Returns the Changes performed."""
    done: list[Change] = []
    for rel in sorted({f.path for f in findings}):
        target = root / rel
        if not target.exists():
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
