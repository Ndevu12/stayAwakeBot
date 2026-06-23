#!/usr/bin/env python3
"""Parse config/urls.yml into resolved UrlCheckConfig objects.

Single responsibility: configuration → domain objects (the merge logic that used
to live in checker_helpers.merge_settings).
"""
from __future__ import annotations

from pathlib import Path

from shared.config import load_yaml
from health.models import UrlCheckConfig


def merge_settings(settings: dict, u: dict) -> UrlCheckConfig:
    return UrlCheckConfig(
        name=u["name"],
        url=u["url"],
        expected_status=u.get("expected_status"),
        max_response_ms=u.get("max_response_ms"),
        check_ssl=u.get("check_ssl", False),
        keyword=u.get("keyword"),
        tags=u.get("tags", []),
        timeout_seconds=int(u.get("timeout_seconds", settings.get("timeout_seconds", 10))),
        retries=int(u.get("retries", settings.get("retries", 0))),
        user_agent=settings.get("user_agent", "StayAwakeBot/1.0"),
        alert_on_failure=settings.get("alert_on_failure", True),
        alert_on_recovery=settings.get("alert_on_recovery", True),
        consecutive_failures_before_alert=int(
            settings.get("consecutive_failures_before_alert", 1)),
    )


def load_config(path: str | Path) -> tuple[dict, list[UrlCheckConfig]]:
    data = load_yaml(path)
    settings = data.get("settings", {})
    configs = [merge_settings(settings, u) for u in data.get("urls", [])]
    return settings, configs
