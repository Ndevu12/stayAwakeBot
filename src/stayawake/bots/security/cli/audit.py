#!/usr/bin/env python3
"""Entrypoint: local security hygiene audit. `python -m stayawake.bots.security.cli.audit`."""
from __future__ import annotations

import argparse
import sys

from stayawake.bots.security import hygiene
from stayawake.core import auth


def main() -> None:
    p = argparse.ArgumentParser(
        description="StayAwakeBot local security hygiene audit (credentials + editor + branch protection)")
    p.add_argument("--repo", metavar="OWNER/NAME",
                   help="also audit this repo's default-branch protection (needs a token)")
    p.add_argument("--branch", default="main", help="branch to check protection for (default: main)")
    p.add_argument("--fail-on-issues", action="store_true",
                   help="exit non-zero if any warning-level issue is found")
    a = p.parse_args()

    token, _ = auth.resolve_token()
    if a.repo and not token:
        print(auth.no_credential_hint("auditing branch protection") +
              " Skipping the branch-protection check.\n")
    issues = hygiene.check_credentials() + hygiene.check_vscode() \
        + hygiene.check_branch_protection(a.repo, token, a.branch)
    print(hygiene.render(issues))
    warnings = [i for i in issues if i.severity == "warning"]
    sys.exit(1 if (a.fail_on_issues and warnings) else 0)


if __name__ == "__main__":
    main()
