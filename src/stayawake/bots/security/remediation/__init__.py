#!/usr/bin/env python3
"""Remediation engine — turn findings into safe, reversible changes. Split per concern:
`changes` (structure-safe transforms: quarantine, exact-line / JSON-key removal) and `recovery`
(code-loader git-recovery / gated seam-excision / defer). This package re-exports the flat API so
callers import unchanged (`from stayawake.bots.security import remediation`)."""
from __future__ import annotations

from stayawake.bots.security.remediation.changes import (
    is_auto_fixable, quarantine_path, Change, plan, strip_gitignore_text,
    strip_settings_autorun, ensure_ignored, quarantine_residual, apply, _backup)
from stayawake.bots.security.remediation.recovery import (
    Recovery, Manual, Suggested, codeloader_content_sig, classify_recovery,
    apply_recovery, apply_suggested,
    _carries_payload, _concealment_seam, _is_packed_line, _line_is_pure_payload,
    _seam_strip, _shim_is_dead, _stmt_is_payload, _worm_shim_block)
# Defer-reason constants live in models; re-export so `remediation.<REASON>` resolves as before.
from stayawake.bots.security.models import (
    BORN_INFECTED, INTRINSIC_MATCH, LEGIT_CHANGES, UNTRACKED, NO_VCS, INSPECT_FAILED)
# Module singleton re-exported so `mock.patch.object(remediation.gitutil, …)` still patches globally.
from stayawake.lib import git as gitutil

__all__ = [
    "is_auto_fixable", "quarantine_path", "Change", "plan", "strip_gitignore_text",
    "strip_settings_autorun", "ensure_ignored", "quarantine_residual", "apply",
    "Recovery", "Manual", "Suggested", "codeloader_content_sig", "classify_recovery",
    "apply_recovery", "apply_suggested",
    "BORN_INFECTED", "INTRINSIC_MATCH", "LEGIT_CHANGES", "UNTRACKED", "NO_VCS", "INSPECT_FAILED",
    "gitutil",
]
