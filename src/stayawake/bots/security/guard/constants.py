#!/usr/bin/env python3
"""Shared constants for `saw guard` — the canonical Strix action, workflow paths, setup branch."""
from __future__ import annotations

# The canonical Strix action. Detection is scoped to it (a fork/mirror is out of scope for v1).
STRIX_OWNER, STRIX_REPO = "Ndevu12", "strix"
WORKFLOW_DIR = ".github/workflows"
WORM_GUARD_FILE = f"{WORKFLOW_DIR}/worm-guard.yml"   # created when no Strix gate exists yet
SETUP_BRANCH = "security/guard-setup"                # rolling branch for the `--pr` install/bump
