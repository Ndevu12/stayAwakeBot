#!/usr/bin/env python3
"""`saw fix` — clean up worm findings on a branch. Routes to remediator.fix.

Default: PREPARE the fix on a local `security/auto-clean` branch and stop — no push, no PR,
no network. `--pr` also pushes and opens/updates one rolling PR per repo. `--remote` (or
naming `--user`/`--org`) sweeps GitHub repos (ad-hoc selectors → configured targets → your
own repos), cloning each. Scope is LOCAL by default. Each repo's outcome streams live.
(`saw discard` is the inverse.)
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import remediator


def register(sub) -> None:
    p = sub.add_parser("fix", help="prepare a cleanup branch per infected repo (--pr to open a PR)")
    p.add_argument("paths", nargs="*", metavar="TARGETS",
                   help="local repo/dir paths — or, with --remote, owner/repo slugs. "
                        "Omit to fix configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional target (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("--pr", "--open-pr", action="store_true", dest="pr",
                   help="also push the branch and open/update one rolling PR per repo")
    p.add_argument("-r", "--remote", action="store_true",
                   help="sweep GitHub repos (clone → fix → PR): ad-hoc --user/--org/owner-repo, "
                        "else configured targets, else your own repos")
    p.add_argument("--user", action="append", default=[], metavar="USER",
                   help="fix this GitHub user's repos (repeatable; implies --remote)")
    p.add_argument("--org", action="append", default=[], metavar="ORG",
                   help="fix this GitHub org's repos (repeatable; implies --remote)")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress output (plain, instant lines)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    positionals = [*a.paths, *a.extra_paths]
    remote = a.remote or bool(a.user) or bool(a.org)   # naming a GitHub account implies --remote
    return remediator.fix(a.config, pr=a.pr, remote=remote,
                          paths=None if remote else (positionals or None),
                          slugs=(positionals or None) if remote else None,
                          users=a.user or None, orgs=a.org or None, no_stream=a.no_stream)
