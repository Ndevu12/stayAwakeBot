#!/usr/bin/env python3
"""Shared constants for the `saw` CLI.

A dependency-light leaf module (it imports nothing from the `stayawake.cli` package)
so command modules and the dispatcher can import it freely without import cycles.
"""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:                                       # version is derived from the git tag at build time
    __version__ = _pkg_version("stayawakebot")
except PackageNotFoundError:               # running from a source tree without an installed dist
    __version__ = "0+unknown"

DEFAULT_REPORTS = "reports/security"

# Canonical verbs in display order — used by `completion` and the conflict-guard test.
VERBS = ["scan", "fix", "discard", "audit", "search", "intro", "doctor", "completion"]
