#!/usr/bin/env python3
"""Entrypoint: security scan. `python -m security.cli.scan`."""
from __future__ import annotations

import argparse
import sys

from stayawake.bots.security import service


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot security scanner")
    p.add_argument("--config", default="config/security.yml")
    p.add_argument("--local-only", action="store_true", help="skip remote GitHub targets")
    p.add_argument("--fail-on-findings", action="store_true",
                   help="exit non-zero if any infected target (for CI gating)")
    a = p.parse_args()
    sys.exit(service.scan(a.config, a.local_only, a.fail_on_findings))


if __name__ == "__main__":
    main()
