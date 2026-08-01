#!/usr/bin/env python3
"""`saw guard` — detect/grade the Strix CI gate (#1229), install/update it (proposed-only), and
sweep many targets. Split per concern into constants / detect / setup / sweep; this package
re-exports the flat public API so callers import unchanged (`from stayawake.bots.security import
guard`)."""
from __future__ import annotations

from stayawake.bots.security.guard.constants import (
    STRIX_OWNER, STRIX_REPO, WORKFLOW_DIR, WORM_GUARD_FILE, SETUP_BRANCH)
from stayawake.bots.security.guard.detect import (
    StrixRef, classify_pin, find_strix, WormGate, find_worm_gate, Freshness, LatestStrix,
    latest_strix, freshness, GuardStatus, RemoteRead, GateProbe, probe_remote_gate, remote_gate,
    check, render, _context_required)   # _context_required: imported by test_guard directly
from stayawake.bots.security.guard.provision import (
    Pin, SetupPlan, SetupResult, resolve_pin, render_workflow, plan_setup, setup, render_setup)
from stayawake.bots.security.guard.sweep import check_targets, setup_targets
# Re-export the module singletons the submodules use so existing tests keep working with
# `mock.patch.object(guard.<module>, …)` — a module is one object, so patching it here reaches every
# submodule that imported it. (Function-level helpers are patched on their OWN submodule, where their
# caller resolves them: e.g. guard.detect.freshness, guard.sweep.check, guard.provision.resolve_pin.)
from stayawake.lib.adapters import github_api
from stayawake.lib import auth, git as gitutil
from stayawake.bots.security import proposal, resolution

__all__ = [
    "STRIX_OWNER", "STRIX_REPO", "WORKFLOW_DIR", "WORM_GUARD_FILE", "SETUP_BRANCH",
    "StrixRef", "classify_pin", "find_strix", "WormGate", "find_worm_gate", "Freshness",
    "LatestStrix", "latest_strix", "freshness", "GuardStatus", "RemoteRead", "GateProbe",
    "probe_remote_gate", "remote_gate", "check", "render",
    "Pin", "SetupPlan", "SetupResult", "resolve_pin", "render_workflow", "plan_setup", "setup",
    "render_setup", "check_targets", "setup_targets", "github_api", "gitutil",
]
