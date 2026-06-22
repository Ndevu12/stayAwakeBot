#!/usr/bin/env python3
"""Time formatting helpers (single responsibility: timestamps)."""
from __future__ import annotations

from datetime import datetime, timezone


def now_iso() -> str:
    """ISO-8601 timestamp for the current instant (UTC clock, local offset).

    Matches the original report `generated_at` format so history dedup keys are
    unchanged across the refactor.
    """
    return datetime.now(timezone.utc).astimezone().isoformat()


def utc_stamp() -> str:
    """Human-friendly UTC stamp, e.g. '2026-06-22 14:39 UTC'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
