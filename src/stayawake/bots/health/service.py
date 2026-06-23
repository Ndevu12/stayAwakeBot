#!/usr/bin/env python3
"""Availability orchestration: check → report → alert.

Single responsibility: wire the stages together. The CLI calls these; they hold
no detection/formatting logic of their own.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from stayawake.bots.health import checker, reporter, alerter
from stayawake.bots.health.config import load_config
from stayawake.core.io import write_json

REPORTS_DIR = Path("reports")


async def _check_async(config_path: str) -> bool:
    _settings, configs = load_config(config_path)
    results = await checker.run_checks(configs)
    payload = checker.build_latest_payload(results)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    write_json(REPORTS_DIR / "latest.json", payload)
    checker.append_minimal_history(results, payload["generated_at"], REPORTS_DIR)
    any_unhealthy = False
    for r in results:
        print(checker.format_console_line(r))
        any_unhealthy = any_unhealthy or not r.get("healthy")
    return any_unhealthy


def run_check(config_path: str = "config/urls.yml", fail_on_unhealthy: bool = False) -> int:
    """Returns a process exit code (non-fatal by default, like the original)."""
    any_unhealthy = asyncio.run(_check_async(config_path))
    return 1 if (fail_on_unhealthy and any_unhealthy) else 0


def run_report(latest: str = "reports/latest.json") -> None:
    reporter.generate(latest_path=latest)


def run_alert(latest: str = "reports/latest.json", history: str = "reports/history.json") -> None:
    alerter.run(latest, history)
