#!/usr/bin/env python3
"""`saw guard` — detect/grade the SAW Guard CI gate, install/update it (proposed-only), and
sweep many targets. Split per concern into constants / detect / setup / sweep; this package
re-exports the flat public API so callers import unchanged (`from stayawake.bots.security import
guard`)."""
from __future__ import annotations

from stayawake.bots.security.guard.constants import (
    SAW_GUARD_ACTION, SAW_GUARD_NAME, SAW_GUARD_OWNER, SAW_GUARD_REPO, WORKFLOW_DIR, SAW_GUARD_FILE,
    SETUP_BRANCH,
    ActionPin, CHECKOUT_ACTION, SETUP_PYTHON_ACTION)
from stayawake.bots.security.guard.detect import (
    SawGuardRef, classify_pin, find_saw_guard, WormGate, find_worm_gate, Freshness, LatestSawGuard,
    latest_saw_guard, freshness, GuardStatus, RemoteRead, GateProbe, probe_remote_gate, read_error,
    remote_gate, check, render)
from stayawake.bots.security.guard.provision import (
    Pin, SetupPlan, SetupResult, resolve_pin, render_workflow, plan_setup, setup, render_setup)
from stayawake.bots.security.guard.sweep import check_targets, setup_targets, drift_targets
from stayawake.bots.security.guard.pindrift import drift_one, render_drift, DriftOutcome
from stayawake.lib.adapters import github_api
from stayawake.lib import auth, git as gitutil
from stayawake.core import proposal
from stayawake.bots.security import resolution

__all__ = [
    "SAW_GUARD_ACTION", "SAW_GUARD_NAME", "SAW_GUARD_OWNER", "SAW_GUARD_REPO", "WORKFLOW_DIR",
    "SAW_GUARD_FILE", "SETUP_BRANCH",
    "ActionPin", "CHECKOUT_ACTION", "SETUP_PYTHON_ACTION",
    "SawGuardRef", "classify_pin", "find_saw_guard", "WormGate", "find_worm_gate", "Freshness",
    "LatestSawGuard", "latest_saw_guard", "freshness", "GuardStatus", "RemoteRead", "GateProbe",
    "probe_remote_gate", "read_error", "remote_gate", "check", "render",
    "Pin", "SetupPlan", "SetupResult", "resolve_pin", "render_workflow", "plan_setup", "setup",
    "render_setup", "check_targets", "setup_targets", "drift_targets", "drift_one", "render_drift",
    "DriftOutcome", "github_api", "gitutil",
]
