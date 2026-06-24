#!/usr/bin/env python3
"""Entrypoint: run availability checks. `python -m health.cli.check`."""
from __future__ import annotations

import argparse
import sys

from stayawake.bots.health import service


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot availability checker")
    p.add_argument("--config", default="config/urls.yml")
    p.add_argument("--fail-on-unhealthy", action="store_true",
                   help="exit non-zero if any URL is unhealthy (opt-in)")
    p.add_argument("--reports-dir", default=None,
                   help="where to write reports (default: reports); use a scratch dir to "
                        "avoid touching committed reports")
    a = p.parse_args()
    sys.exit(service.run_check(a.config, a.fail_on_unhealthy, a.reports_dir))


if __name__ == "__main__":
    main()
