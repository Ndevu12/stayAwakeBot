#!/usr/bin/env python3
"""Entrypoint: send alerts. `python -m stayawakebot.cli.alert`."""
from __future__ import annotations

import argparse

from stayawakebot.availability import service


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot alerter")
    p.add_argument("--latest", default="reports/latest.json")
    p.add_argument("--history", default="reports/history.json")
    a = p.parse_args()
    service.run_alert(a.latest, a.history)


if __name__ == "__main__":
    main()
