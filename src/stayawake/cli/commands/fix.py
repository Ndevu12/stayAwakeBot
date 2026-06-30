#!/usr/bin/env python3
"""`saw fix` — clean up worm findings on a branch. Routes to remediator.fix.

Default: PREPARE the fix on a local `security/auto-clean` branch and stop — no push, no PR,
no network — leaving it for you to review and push. `--pr` also pushes and opens/updates one
rolling PR per repo; `--remote` sweeps the configured GitHub targets (clone → fix → PR).
Scope is LOCAL by default. Each repo's outcome streams live. (`saw discard` is the inverse.)
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import remediator


def register(sub) -> None:
    p = sub.add_parser("fix", help="prepare a cleanup branch per infected repo (--pr to open a PR)")
    p.add_argument("paths", nargs="*", metavar="PATHS",
                   help="repo/dir paths to fix. Omit to fix configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional path to fix (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("--pr", "--open-pr", action="store_true", dest="pr",
                   help="also push the branch and open/update one rolling PR per repo")
    p.add_argument("-r", "--remote", action="store_true",
                   help="sweep the configured GitHub targets (clone → fix → PR) instead of local repos")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress output (plain, instant lines)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    paths = [*a.paths, *a.extra_paths]
    return remediator.fix(a.config, pr=a.pr, remote=a.remote,
                          paths=paths or None, no_stream=a.no_stream)
