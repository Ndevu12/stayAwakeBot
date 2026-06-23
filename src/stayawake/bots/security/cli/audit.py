#!/usr/bin/env python3
"""Entrypoint: local security hygiene audit. `python -m stayawake.bots.security.cli.audit`."""
from __future__ import annotations

import argparse
import sys

from stayawake.bots.security import hygiene


def main() -> None:
    p = argparse.ArgumentParser(
        description="StayAwakeBot local security hygiene audit (credentials + editor)")
    p.add_argument("--fail-on-issues", action="store_true",
                   help="exit non-zero if any warning-level issue is found")
    a = p.parse_args()

    issues = hygiene.audit()
    print(hygiene.render(issues))
    warnings = [i for i in issues if i.severity == "warning"]
    sys.exit(1 if (a.fail_on_issues and warnings) else 0)


if __name__ == "__main__":
    main()
