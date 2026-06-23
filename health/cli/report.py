#!/usr/bin/env python3
"""Entrypoint: build reports. `python -m health.cli.report`."""
from __future__ import annotations

import argparse

from health import service


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot reporter")
    p.add_argument("--latest", default="reports/latest.json")
    a = p.parse_args()
    service.run_report(a.latest)


if __name__ == "__main__":
    main()
