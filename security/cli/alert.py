#!/usr/bin/env python3
"""Entrypoint: security alerts. `python -m security.cli.alert`."""
from __future__ import annotations

import argparse

from security import alerter


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot security alerter")
    p.add_argument("--latest", default="reports/security/latest.json")
    a = p.parse_args()
    alerter.run(latest_path=a.latest)


if __name__ == "__main__":
    main()
