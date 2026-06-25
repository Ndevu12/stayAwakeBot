#!/usr/bin/env python3
"""`saw scan` — hunt supply-chain worms. Routes to security.service.scan."""
from __future__ import annotations

import argparse

from stayawake.bots.security import service


def add_scan_args(p: argparse.ArgumentParser) -> None:
    """The path/config/reports options shared by `scan` and the `run` pipeline."""
    p.add_argument("paths", nargs="*", metavar="PATHS",
                   help="repo/dir paths to scan (local). Omit to scan the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional path to scan (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("-L", "--local", "--local-only", action="store_true", dest="local",
                   help="skip remote GitHub targets — scan local paths only")
    p.add_argument("-d", "--reports-dir", default=None, dest="reports_dir",
                   help="where to write reports (default: reports/security)")


def register(sub) -> None:
    p = sub.add_parser("scan", aliases=["s", "sc"], help="hunt supply-chain worms")
    add_scan_args(p)
    p.add_argument("-f", "--fail", "--fail-on-findings", action="store_true", dest="fail",
                   help="exit non-zero if any target is infected (CI gate)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    paths = [*a.paths, *a.extra_paths]
    return service.scan(a.config, a.local, a.fail, a.reports_dir, paths or None)
