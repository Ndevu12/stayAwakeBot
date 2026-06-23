#!/usr/bin/env python3
"""Entrypoint: send alerts. `python -m health.cli.alert`."""
from __future__ import annotations

import argparse

from stayawake.bots.health import service


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot alerter")
    p.add_argument("--latest", default="reports/latest.json")
    p.add_argument("--history", default="reports/history.json")
    a = p.parse_args()
    service.run_alert(a.latest, a.history)


if __name__ == "__main__":
    main()
