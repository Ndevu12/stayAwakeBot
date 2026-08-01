#!/usr/bin/env python3
"""Shared constants for `saw fix` / `saw discard` PR flows."""
from __future__ import annotations

FIX_BRANCH = "security/auto-clean"

ISSUE_LABEL = "stayawake-security"  # de-dup marker for the issue fallback

PARTIAL_LABEL = "security: partial" # marks a PR that fixes SOME but not all indicators (#1183)
