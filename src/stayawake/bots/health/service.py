#!/usr/bin/env python3
"""Availability orchestration: check → refresh the one status issue.

Single responsibility: wire the stages together. The renewed sentinel writes NO report files and
commits NOTHING — the single 'Availability status' issue (see `alerter`) is the whole store.
"""
from __future__ import annotations

import asyncio

from stayawake.bots.health import checker, alerter
from stayawake.bots.health.config import load_config


async def _check_async(config_path: str) -> bool:
    settings, configs = load_config(config_path)
    results = await checker.run_checks(configs)
    alerter.publish(results, settings)   # the one dashboard issue IS the store — no files, no commit
    any_unhealthy = False
    for r in results:
        print(checker.format_console_line(r))
        any_unhealthy = any_unhealthy or not r.get("healthy")
    return any_unhealthy


def run_check(config_path: str = "config/urls.yml", fail_on_unhealthy: bool = False) -> int:
    """Check every URL and refresh the one dashboard issue. Returns a process exit code
    (non-fatal by default).

    The check ALWAYS runs. `fail_on_unhealthy` decides only what the exit code says about the
    result — it must never decide whether the work happens. Evaluating the two in one `and`
    short-circuited the check away whenever the flag was off, so a monitor invoked without it
    reported success having contacted nothing."""
    any_unhealthy = asyncio.run(_check_async(config_path))
    return 1 if (fail_on_unhealthy and any_unhealthy) else 0
