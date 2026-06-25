#!/usr/bin/env python3
"""`saw fix` — remediate findings (dry-run by default). Routes to remediator."""
from __future__ import annotations

import argparse

from stayawake.bots.security import remediator


def register(sub) -> None:
    p = sub.add_parser("fix", help="remediate findings (dry-run by default)")
    p.add_argument("-c", "--config", default="config/security.yml")
    p.add_argument("--apply", action="store_true",
                   help="apply local fixes (backed up) and commit to a branch")
    p.add_argument("--pr", "--open-pr", action="store_true", dest="pr",
                   help="with --apply: push a fix branch and open/update one PR per repo")
    p.add_argument("--remote", action="store_true",
                   help="sweep configured GitHub targets and open/update a fix PR per repo")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    if a.remote:
        # submit_org_prs returns the COUNT of repos that got a PR, not an exit code —
        # a successful sweep must still exit 0 (matches the legacy remediate script).
        remediator.submit_org_prs(a.config)
        return 0
    remediator.remediate(a.config, apply=a.apply, open_pr=a.pr)
    return 0
