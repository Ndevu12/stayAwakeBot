#!/usr/bin/env python3
"""Shared constants for the `saw` CLI.

A dependency-light leaf module (it imports nothing from the `stayawake.cli` package)
so command modules and the dispatcher can import it freely without import cycles.
"""
from __future__ import annotations

from stayawake.utils.release import RELEASE as __version__

DEFAULT_REPORTS = "reports/security"

VERBS = ["scan", "fix", "discard", "audit", "harden", "guard", "govern", "search", "intro", "doctor", "completion"]
