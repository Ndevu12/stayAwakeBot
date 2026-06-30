#!/usr/bin/env python3
"""`saw discard` — the inverse of `saw fix`. Routes to remediator.discard.

Removes what `fix` produced; only ever touches the auto-generated `security/auto-clean`
branch, never a real branch. `--branch`/`-br` deletes it locally and on its remote (pure
git — works even when the GitHub API is unreachable; deleting the remote branch auto-closes
its PR). `--pr` closes the open PR via the API (leaves the branch). Scope is LOCAL by default;
`--remote` (or naming `--user`/`--org`) sweeps GitHub repos (ad-hoc selectors → configured
targets → your own repos). At least one of `--branch`/`--pr` is required.
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import remediator


def register(sub) -> None:
    p = sub.add_parser("discard", help="undo `saw fix`: delete the auto-clean branch and/or close its PR")
    p.add_argument("paths", nargs="*", metavar="TARGETS",
                   help="local repo/dir paths — or, with --remote, owner/repo slugs. "
                        "Omit to act on configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional target (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("-br", "--branch", action="store_true",
                   help="delete the security/auto-clean branch locally and on its remote (git only)")
    p.add_argument("--pr", "--close-pr", action="store_true", dest="pr",
                   help="close the open security/auto-clean PR (leaves the branch)")
    p.add_argument("-r", "--remote", action="store_true",
                   help="sweep GitHub repos: ad-hoc --user/--org/owner-repo, else configured "
                        "targets, else your own repos")
    p.add_argument("--user", action="append", default=[], metavar="USER",
                   help="act on this GitHub user's repos (repeatable; implies --remote)")
    p.add_argument("--org", action="append", default=[], metavar="ORG",
                   help="act on this GitHub org's repos (repeatable; implies --remote)")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress output (plain, instant lines)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    positionals = [*a.paths, *a.extra_paths]
    remote = a.remote or bool(a.user) or bool(a.org)   # naming a GitHub account implies --remote
    return remediator.discard(a.config, branch=a.branch, pr=a.pr, remote=remote,
                              paths=None if remote else (positionals or None),
                              slugs=(positionals or None) if remote else None,
                              users=a.user or None, orgs=a.org or None, no_stream=a.no_stream)
