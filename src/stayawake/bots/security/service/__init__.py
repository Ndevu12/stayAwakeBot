#!/usr/bin/env python3
"""Security orchestration: resolve targets → scan → deliver via sinks.

Split per concern: `config` (YAML+flags → `ScanOptions`, advisory-DB gate) / `report`
(per-target verdict tag + written-report pointer) / `run` (the `scan` orchestration + its
fleet/finding spill thresholds). Detection lives in the matchers; delivery lives in the sinks;
this package performs NO output I/O of its own. Never executes scanned code; remote repos are
cloned read-only into sandboxes and removed after.

Flat re-export of the PUBLIC entrypoint (`scan`) so callers import unchanged; internal helpers
(`_options`, `_resolve_remote`, the spill thresholds, …) live in their submodule and are reached
at `service.config.<h>` / `service.run.<h>`.
"""
from __future__ import annotations

from stayawake.bots.security.service.run import scan
# Module singletons re-exported so `service.github_api` / `service.auth` resolve (the targeting
# tests patch attributes on these). A module is one object, so patching an attribute here mutates
# the same object `resolution.py` consumes transitively — the patch reaches the scan path.
from stayawake.lib.adapters import github_api
from stayawake.lib import auth

__all__ = ["scan", "github_api", "auth"]
