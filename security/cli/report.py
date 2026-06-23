#!/usr/bin/env python3
"""Entrypoint: security badge + status. `python -m security.cli.report`."""
from __future__ import annotations

import argparse

from security import reporter


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot security reporter")
    p.add_argument("--latest", default="reports/security/latest.json")
    a = p.parse_args()
    reporter.generate(latest_path=a.latest)


if __name__ == "__main__":
    main()
