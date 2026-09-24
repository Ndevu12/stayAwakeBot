#!/usr/bin/env python3
"""Map findings to structure-safe changes and apply them."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.harden import jsonc
from stayawake.bots.security.models import CONFIRMED, ROLLBACK_DIR, SAW_DIR
from stayawake.bots.security.remediation.footprint import REMOVE_FILE
from stayawake.bots.security.remediation.oracle import (ABSENT, CARRIES, CHANGED, REFUSED,
                                                        UNREADABLE)

_ACTIONS = {
    REMOVE_FILE: "remove",
    "remove-foreign-vscode": "vscode",
    "strip-gitignore-markers": "strip-gitignore",
}
_GITIGNORE_MARKER_PATTERNS = None

_ROLLBACK_COMMENT = "# Remediation rollback copies (kept local, never committed)"
_ROLLBACK_PATTERNS = (SAW_DIR + "/",)


def is_auto_fixable(finding) -> bool:
    """True when a confirmed finding has a known automatic remediation."""
    if getattr(finding, "confidence", None) != CONFIRMED:
        return False
    return getattr(finding, "remediation", "manual") in _ACTIONS


def rollback_path(root: Path) -> Path:
    return root / ROLLBACK_DIR


@dataclass(frozen=True)
class Change:
    action: str
    path: str
    detail: str = ""


def plan(findings) -> list[Change]:
    """Map findings to a deduped list of changes (pure — no filesystem access)."""
    changes: dict[tuple[str, str], Change] = {}
    for f in findings:
        if not is_auto_fixable(f):
            continue
        action = _ACTIONS[getattr(f, "remediation", "manual")]
        path = f.path
        if not path or Path(path) in (Path("."), Path("..")):
            continue
        if action == "vscode":
            if f.path.endswith("tasks.json"):
                c = Change("remove", f.path, "VS Code auto-run task harness")
            elif f.path.endswith("settings.json"):
                c = Change("strip-settings", f.path, "remove allowAutomaticTasks/tasks")
            else:
                continue
        else:
            c = Change(action, path, f.description[:60])
        changes[(c.action, c.path)] = c
    return list(changes.values())


def _gitignore_marker_patterns():
    """The git-marker patterns for `.gitignore`, compiled once from the live signature DB."""
    global _GITIGNORE_MARKER_PATTERNS
    if _GITIGNORE_MARKER_PATTERNS is None:
        from stayawake.bots.security import signatures as _sigs
        from stayawake.bots.security.remediation import footprint
        flat = [s for group in _sigs.load_signatures().values() for s in group]
        _GITIGNORE_MARKER_PATTERNS = footprint._marker_patterns(".gitignore", flat)
    return _GITIGNORE_MARKER_PATTERNS


def strip_gitignore_text(text: str) -> str:
    """`text` with every worm-marker line the signatures name removed; unchanged if none match."""
    from stayawake.bots.security.remediation import footprint
    stripped = footprint.line_marker_strip(text, _gitignore_marker_patterns())
    return text if stripped is None else stripped


def strip_settings_autorun(text: str) -> str:
    """`text` with the automatic-task setting taken out, and nothing else about the file changed.

    Takes the file's text. Returns it unchanged when the setting is not there exactly once, so a
    file saw cannot edit precisely is left for a person rather than rewritten.
    """
    done = jsonc.remove_key(text, "task.allowAutomaticTasks")
    return done[0] if done else text


def ensure_ignored(root: Path) -> bool:
    """Append the rollback-store ignore patterns to `root/.gitignore`. True if the file changed."""
    gi = root / ".gitignore"
    if gi.is_symlink():
        return False
    text = gi.read_text(encoding="utf-8", errors="replace") if gi.exists() else ""
    present = {l.strip() for l in text.splitlines()}
    missing = [p for p in _ROLLBACK_PATTERNS if p not in present]
    if not missing:
        return False
    block: list[str] = []
    if _ROLLBACK_COMMENT not in present:
        block.append(_ROLLBACK_COMMENT)
    block += missing
    head = (text.rstrip("\n") + "\n\n") if text.strip() else ""
    gi.write_text(head + "\n".join(block) + "\n", encoding="utf-8")
    return True


def _dest_ready(rollback: Path, dest: Path) -> bool:
    try:
        if dest.is_symlink() or dest.exists():
            return False
        try:
            lexical = dest.relative_to(rollback)
        except ValueError:
            return False
        if lexical == Path(".") or ".." in lexical.parts:
            return False
        q = rollback.resolve()
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


def _backup(root: Path, rel: str, rollback: Path | None) -> None:
    if rollback is None:
        return
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        return
    src = root / rel
    if not src.exists():
        return
    if src.is_symlink():
        return
    dest = rollback / rel
    if not _dest_ready(rollback, dest):
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not _dest_ready(rollback, dest):
        return
    if src.is_dir():
        shutil.copytree(src, dest, symlinks=True)
    else:
        shutil.copy2(src, dest, follow_symlinks=False)


def _erase(target: Path) -> None:
    """Take a file off the disk. Takes the path.

    A file more than one name points at has its bytes emptied first, so the content goes with the
    name rather than staying live under the other one.
    """
    if not target.is_symlink():
        try:
            if target.stat().st_nlink > 1:
                with open(target, "wb"):
                    pass
        except OSError:
            pass
    target.unlink()


def _skipped(on_skip, path: str, reason: str) -> None:
    """Tell the caller a change was not applied. Takes the callback, the path and the reason."""
    if on_skip is not None:
        on_skip(path, reason)


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


def remove_residual(root: Path, findings, rollback: Path) -> list["Change"]:
    """Back up and remove each remaining flagged path."""
    done: list[Change] = []
    for rel in sorted({f.path for f in findings}):
        target = root / rel
        if not target.exists() or not _delete_stays_in(root, target):
            continue
        _backup(root, rel, rollback)
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
        done.append(Change("remove", rel, "residual after remediation"))
    return done


def apply(root: Path, changes: list[Change], rollback: Path | None = None, *,
          condemned=None, on_skip=None) -> list[Change]:
    """Apply changes in-place under `root`, backing up originals to `rollback`.

    Takes the tree, the changes, a rollback store or None, optionally `condemned(path) -> str`,
    and optionally `on_skip(path, reason)`. Returns the changes that were applied.

    Idempotent: a change whose target is already gone/clean is skipped.
    """
    applied: list[Change] = []
    for c in changes:
        target = root / c.path
        if c.action == "remove":
            verdict = condemned(c.path) if condemned is not None else CARRIES
            if verdict not in (CARRIES, CHANGED):
                _skipped(on_skip, c.path, verdict)
                continue
            if not target.exists() and not target.is_symlink():
                _skipped(on_skip, c.path, ABSENT)
                continue
            if not _delete_stays_in(root, target):
                _skipped(on_skip, c.path, REFUSED)
                continue
            _backup(root, c.path, rollback)
            try:
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    _erase(target)
            except OSError:
                _skipped(on_skip, c.path, REFUSED)
                continue
            applied.append(c)
        elif c.action in ("strip-gitignore", "strip-settings"):
            if not target.exists():
                _skipped(on_skip, c.path, ABSENT)
                continue
            if not is_safe_write_target(target, root):
                _skipped(on_skip, c.path, REFUSED)
                continue
            try:
                if target.stat().st_nlink > 1:
                    _skipped(on_skip, c.path, REFUSED)
                    continue
                original = target.read_bytes().decode("utf-8")
            except OSError:
                _skipped(on_skip, c.path, UNREADABLE)
                continue
            except UnicodeDecodeError:
                _skipped(on_skip, c.path, REFUSED)
                continue
            if c.action == "strip-gitignore":
                new = strip_gitignore_text(original)
            else:
                new = strip_settings_autorun(original)
            if new == original:
                _skipped(on_skip, c.path, REFUSED)
                continue
            _backup(root, c.path, rollback)
            try:
                target.write_text(new, encoding="utf-8")
            except OSError:
                _skipped(on_skip, c.path, REFUSED)
                continue
            if condemned is not None and condemned(c.path) == CARRIES:
                _skipped(on_skip, c.path, REFUSED)
                continue
            applied.append(c)
    return applied
