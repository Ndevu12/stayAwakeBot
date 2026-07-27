#!/usr/bin/env python3
"""Cross-bot AuthN/AuthZ domain — capability gate before privileged side effects.

    utils/ → lib/ (credential adapters) → core/identity (this package) → bots/ → cli/

Bots call `require(Intent.…)` and stop on Deny — never clone/push first and guess why.
Phase 1 (`saw auth app register`) is the supported operator-managed App path; a
marketplace App remains optional backlog (#1277).
"""
from __future__ import annotations

from stayawake.core.identity.capabilities import Capability
from stayawake.core.identity.classify import PushFailure, classify_push_stderr, push_failure_message
from stayawake.core.identity.gate import require
from stayawake.core.identity.intents import Intent, requirements
from stayawake.core.identity.outcomes import Decision, UpgradePath
from stayawake.core.identity.session import Session, resolve_session

__all__ = [
    "Capability", "Intent", "Decision", "UpgradePath", "Session",
    "PushFailure", "require", "resolve_session", "requirements",
    "classify_push_stderr", "push_failure_message",
]
