#!/usr/bin/env python3
"""Remediation engine — turn findings into safe, reversible changes. Split per concern:
`changes` (structure-safe transforms: quarantine, exact-line / JSON-key removal) and the code-loader
recovery pipeline — `gates` (pure payload analysis + the surgical seam-strip), `classify` (decide
recover / suggest / defer), `writeback` (the side-effecting apply). This package re-exports the flat
API so callers import unchanged (`from stayawake.bots.security import remediation`)."""
from __future__ import annotations

# The flat PUBLIC API — the package facade. Internal gate helpers (`_seam_strip`, `_carries_payload`,
# …) are NOT re-exported here: they belong to their own module and are reached at
# `remediation.gates.<helper>` / `remediation.changes._backup` (their real home).
from stayawake.bots.security.remediation.changes import (
    is_auto_fixable, quarantine_path, Change, plan, strip_gitignore_text,
    strip_settings_autorun, ensure_ignored, quarantine_residual, apply)
from stayawake.bots.security.remediation.gates import codeloader_content_sig
from stayawake.bots.security.remediation.classify import (
    Recovery, Manual, Suggested, classify_recovery)
from stayawake.bots.security.remediation.writeback import apply_recovery, apply_suggested
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
