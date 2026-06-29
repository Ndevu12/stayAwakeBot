#!/usr/bin/env python3
"""`saw fix` — clean up worm findings by opening a pull request. Routes to remediator.fix.

Cleanup is delivered as a PR (the review gate), never an in-place edit — so there is no
apply/preview flag: running `fix` opens (or updates) one rolling `security/auto-clean` PR
per infected repo, and re-runs update it rather than opening duplicates. Scope is LOCAL by
default (given paths / configured globs / the current repo); `--remote` sweeps the
configured GitHub targets. Each repo's outcome streams live.
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import remediator


def register(sub) -> None:
    p = sub.add_parser("fix", help="open/update a cleanup PR per infected repo")
    p.add_argument("paths", nargs="*", metavar="PATHS",
                   help="repo/dir paths to fix. Omit to fix configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional path to fix (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("-r", "--remote", action="store_true",
                   help="fix the configured GitHub targets instead of local repos")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress output (plain, instant lines)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    paths = [*a.paths, *a.extra_paths]
    return remediator.fix(a.config, remote=a.remote, paths=paths or None, no_stream=a.no_stream)
