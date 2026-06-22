#!/usr/bin/env python3
"""Entrypoint: auto-remediate worm findings in local repos.

Dry-run by default.
  --apply            write fixes locally (backed up) and commit to a branch
  --apply --open-pr  push a stable `security/auto-clean` branch and open ONE rolling
                     PR per repo (updates the existing PR instead of duplicating).
                     Needs GH_SECURITY_TOKEN / GITHUB_TOKEN with PR write scope.

`python -m stayawakebot.cli.security_remediate [--apply] [--open-pr]`
"""
from __future__ import annotations

import argparse

from stayawakebot.security import remediator


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot security remediator")
    p.add_argument("--config", default="config/security.yml")
    p.add_argument("--apply", action="store_true",
                   help="apply fixes (default is dry-run)")
    p.add_argument("--open-pr", action="store_true",
                   help="with --apply: push a fix branch and open/update one PR per repo")
    a = p.parse_args()
    remediator.remediate(a.config, apply=a.apply, open_pr=a.open_pr)


if __name__ == "__main__":
    main()
