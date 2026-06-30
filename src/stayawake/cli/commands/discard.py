#!/usr/bin/env python3
"""`saw discard` — the inverse of `saw fix`. Routes to remediator.discard.

Removes what `fix` produced; only ever touches the auto-generated `security/auto-clean`
branch, never a real branch. `--branch`/`-br` deletes it locally and on its remote (pure
git — works even when the GitHub API is unreachable; deleting the remote branch auto-closes
its PR). `--pr` closes the open PR via the API (leaves the branch). Scope is LOCAL by
default; `--remote` sweeps the configured GitHub targets. At least one of `--branch`/`--pr`
is required. Each repo's outcome streams live.
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import remediator


def register(sub) -> None:
    p = sub.add_parser("discard", help="undo `saw fix`: delete the auto-clean branch and/or close its PR")
    p.add_argument("paths", nargs="*", metavar="PATHS",
                   help="repo/dir paths. Omit to act on configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional path (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("-br", "--branch", action="store_true",
                   help="delete the security/auto-clean branch locally and on its remote (git only)")
    p.add_argument("--pr", "--close-pr", action="store_true", dest="pr",
                   help="close the open security/auto-clean PR (leaves the branch)")
    p.add_argument("-r", "--remote", action="store_true",
                   help="sweep the configured GitHub targets instead of local repos")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress output (plain, instant lines)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    paths = [*a.paths, *a.extra_paths]
    return remediator.discard(a.config, branch=a.branch, pr=a.pr, remote=a.remote,
                              paths=paths or None, no_stream=a.no_stream)
