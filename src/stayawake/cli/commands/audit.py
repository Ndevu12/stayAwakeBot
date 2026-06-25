#!/usr/bin/env python3
"""`saw audit` — credential + editor + branch-protection hygiene audit."""
from __future__ import annotations

import argparse

from stayawake.bots.security import hygiene
from stayawake.core import auth


def register(sub) -> None:
    p = sub.add_parser("audit", aliases=["au"], help="hygiene + branch-protection audit")
    p.add_argument("--repo", metavar="OWNER/NAME", default=None,
                   help="also audit this repo's branch protection (needs a token)")
    p.add_argument("-b", "--branch", default="main",
                   help="branch to check protection for (default: main)")
    p.add_argument("-f", "--fail", "--fail-on-issues", action="store_true", dest="fail",
                   help="exit non-zero if any warning-level issue is found")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    token, _ = auth.resolve_token()
    if a.repo and not token:
        print(auth.no_credential_hint("auditing branch protection") +
              " Skipping the branch-protection check.\n")
    issues = (hygiene.check_credentials() + hygiene.check_vscode()
              + hygiene.check_branch_protection(a.repo, token, a.branch))
    print(hygiene.render(issues))
    warnings = [i for i in issues if i.severity == "warning"]
    return 1 if (a.fail and warnings) else 0
