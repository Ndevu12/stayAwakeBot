#!/usr/bin/env python3
"""Entrypoint: auto-remediate worm findings.

Local repos (default — scans config local targets):
  (no flags)         dry-run
  --apply            write fixes locally (backed up) and commit to a branch
  --apply --open-pr  push a stable `security/auto-clean` branch and open ONE rolling,
                     de-duplicated PR per repo

Org-wide (configured GitHub targets):
  --remote           clone each configured repo and open/update its dedup'd fix PR
                     (needs a GitHub credential with repo + PR write scope: an env
                     token or a `gh auth login` session)

`python -m security.cli.remediate [--apply] [--open-pr] [--remote]`
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import remediator


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot security remediator")
    p.add_argument("--config", default=None,
                   help="config file (default: config/security.yml when present, else the current repo)")
    p.add_argument("--apply", action="store_true", help="apply local fixes (default is dry-run)")
    p.add_argument("--open-pr", action="store_true",
                   help="with --apply: push a fix branch and open/update one PR per local repo")
    p.add_argument("--remote", action="store_true",
                   help="sweep configured GitHub targets and open/update a dedup'd fix PR per repo")
    a = p.parse_args()
    if a.remote:
        remediator.submit_org_prs(a.config)
    else:
        remediator.remediate(a.config, apply=a.apply, open_pr=a.open_pr)


if __name__ == "__main__":
    main()
