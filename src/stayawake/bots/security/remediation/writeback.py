#!/usr/bin/env python3
"""Write recovered or stripped file contents, with backup and verify."""
from __future__ import annotations

import shutil
from pathlib import Path

from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.remediation.changes import _backup
from stayawake.bots.security.remediation.gates import (
    _carries_payload, _ext, _seam_strip, _is_subsequence, _safe_to_recover)
from stayawake.bots.security.remediation.classify import Recovery, Suggested


def _backup_write_verify(root: Path, rel: str, new_text: str, quarantine: Path, content_sig) -> bool:
    """Write `new_text` after backing up. Revert if the write does not verify."""
    target = root / rel
    try:
        if target.stat().st_nlink > 1:
            return False
    except OSError:
        return False
    _backup(root, rel, quarantine)
    target.write_text(new_text, encoding="utf-8")
    restored = target.read_text(encoding="utf-8", errors="replace")
    if restored != new_text or _carries_payload(restored, content_sig):
        backup = quarantine / rel
        if backup.exists():
            shutil.copy2(backup, target)
        return False
    return True


def _apply_seam_excision(root: Path, rel: str, expected: str, quarantine: Path, content_sig) -> bool:
    """Write a seam excision if the live file still produces `expected`."""
    target = root / rel
    if not expected or not is_safe_write_target(target, root):
        return False
    if not target.exists() or _carries_payload(expected, content_sig):
        return False
    current = target.read_text(encoding="utf-8", errors="replace")
    if _seam_strip(current, _ext(rel), content_sig) != expected:
        return False
    return _backup_write_verify(root, rel, expected, quarantine, content_sig)


def _apply_whole_file_restore(root: Path, rel: str, expected: str, quarantine: Path, content_sig) -> bool:
    """Write a whole-file restore if `expected` is a safe reduction of the live file."""
    target = root / rel
    if not expected or not is_safe_write_target(target, root):
        return False
    if not target.exists() or _carries_payload(expected, content_sig):
        return False
    current = target.read_text(encoding="utf-8", errors="replace")
    if not _safe_to_recover(current, expected, content_sig) or not _is_subsequence(expected, current):
        return False
    return _backup_write_verify(root, rel, expected, quarantine, content_sig)


def apply_recovery(repo, rec: Recovery, quarantine: Path, content_sig) -> bool:
    """Write `rec.clean_text` after backing up. Revert if the write does not verify."""
    root = Path(repo)
    if rec.excised:
        return _apply_seam_excision(root, rec.path, rec.clean_text, quarantine, content_sig)
    target = root / rec.path
    if not rec.clean_text or not is_safe_write_target(target, root):
        return False
    if not target.exists() or _carries_payload(rec.clean_text, content_sig):
        return False
    current = target.read_text(encoding="utf-8", errors="replace")
    if not _safe_to_recover(current, rec.clean_text, content_sig):
        return False
    if not _is_subsequence(rec.clean_text, current):
        return False
    return _backup_write_verify(root, rec.path, rec.clean_text, quarantine, content_sig)


def apply_suggested(repo, sug: "Suggested", quarantine: Path, content_sig) -> bool:
    """Write a computed strip or restore."""
    if getattr(sug, "apply_mode", "seam") == "restore":
        return _apply_whole_file_restore(Path(repo), sug.path, sug.excised_text, quarantine, content_sig)
    return _apply_seam_excision(Path(repo), sug.path, sug.excised_text, quarantine, content_sig)
