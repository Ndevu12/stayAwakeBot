#!/usr/bin/env python3
"""Security orchestration: resolve targets → scan → deliver via sinks."""
from __future__ import annotations

from stayawake.bots.security.service.run import scan
# Module singletons re-exported so `service.github_api` / `service.auth` resolve (the targeting
# tests patch attributes on these). A module is one object, so patching an attribute here mutates
# the same object `resolution.py` consumes transitively — the patch reaches the scan path.
from stayawake.lib.adapters import github_api
from stayawake.lib import auth

__all__ = ["scan", "github_api", "auth"]
