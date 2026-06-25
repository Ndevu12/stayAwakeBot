#!/usr/bin/env python3
"""Availability orchestration: check → report → alert.

Single responsibility: wire the stages together. The CLI calls these; they hold
no detection/formatting logic of their own.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from stayawake.bots.health import checker, reporter, alerter
from stayawake.bots.health.config import load_config
from stayawake.core.io import write_json, resolve_writable_dir

REPORTS_DIR = Path("reports")


async def _check_async(config_path: str, reports_dir: str | Path | None = None) -> bool:
    settings, configs = load_config(config_path)
    results = await checker.run_checks(configs)
    payload = checker.build_latest_payload(results)
    # Precedence: explicit arg / --reports-dir → STAYAWAKE_REPORTS_DIR env → settings → default.
    rdir = Path(reports_dir or os.environ.get("STAYAWAKE_REPORTS_DIR")
                or settings.get("reports_dir") or REPORTS_DIR)
    rdir = resolve_writable_dir(rdir, label="health reports")
    write_json(rdir / "latest.json", payload)
    checker.append_minimal_history(results, payload["generated_at"], rdir)
    any_unhealthy = False
    for r in results:
        print(checker.format_console_line(r))
        any_unhealthy = any_unhealthy or not r.get("healthy")
    return any_unhealthy


def run_check(config_path: str = "config/urls.yml", fail_on_unhealthy: bool = False,
              reports_dir: str | Path | None = None) -> int:
    """Returns a process exit code (non-fatal by default, like the original)."""
    any_unhealthy = asyncio.run(_check_async(config_path, reports_dir))
    return 1 if (fail_on_unhealthy and any_unhealthy) else 0


def run_report(latest: str = "reports/latest.json") -> None:
    reporter.generate(latest_path=latest)


def run_alert(latest: str = "reports/latest.json", history: str = "reports/history.json") -> None:
    alerter.run(latest, history)
