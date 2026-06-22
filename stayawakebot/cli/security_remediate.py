#!/usr/bin/env python3
"""Entrypoint: auto-remediate worm findings in local repos.

Dry-run by default; `--apply` writes fixes (backed up) and commits to a branch.
`python -m stayawakebot.cli.security_remediate [--apply]`
"""
from __future__ import annotations

import argparse

from stayawakebot.security import remediator


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot security remediator")
    p.add_argument("--config", default="config/security.yml")
    p.add_argument("--apply", action="store_true",
                   help="apply fixes (default is dry-run); backs up + commits to a branch")
    a = p.parse_args()
    remediator.remediate(a.config, apply=a.apply)


if __name__ == "__main__":
    main()
