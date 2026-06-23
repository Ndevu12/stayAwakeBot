#!/usr/bin/env python3
"""Availability domain types."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class UrlCheckConfig:
    """Fully-resolved per-URL check config (global settings merged with overrides)."""

    name: str
    url: str
    expected_status: int | None
    max_response_ms: int | None
    check_ssl: bool
    keyword: str | None
    tags: list[str]
    timeout_seconds: int
    retries: int
    user_agent: str
    alert_on_failure: bool
    alert_on_recovery: bool
    consecutive_failures_before_alert: int
