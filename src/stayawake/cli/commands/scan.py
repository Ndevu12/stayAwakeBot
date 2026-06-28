#!/usr/bin/env python3
"""`saw scan` — hunt supply-chain worms. Routes to security.service.scan.

Terminal-first: by default the result is rendered to the terminal and NOTHING is written
to disk. The verdict is the exit code (0 clean / 1 infected), unconditionally. Persisting
or alerting is opt-in: --json (machine stdout), --sarif FILE, -d DIR (both redacted),
--alert (GitHub issue + Slack).
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import service


def add_scan_args(p: argparse.ArgumentParser) -> None:
    """The path/config/output options for `scan`."""
    p.add_argument("paths", nargs="*", metavar="PATHS",
                   help="repo/dir paths to scan (local). Omit to scan the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional path to scan (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("-L", "--local", "--local-only", action="store_true", dest="local",
                   help="skip remote GitHub targets — scan local paths only")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress/typewriter output (plain, instant lines)")


def register(sub) -> None:
    p = sub.add_parser("scan", aliases=["s", "sc"], help="hunt supply-chain worms")
    add_scan_args(p)
    # Opt-in output surfaces (terminal-first: none of these is on by default).
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON to stdout (full evidence; progress on stderr)")
    p.add_argument("--sarif", default=None, metavar="FILE",
                   help="write a SARIF 2.1.0 report to FILE for code-scanning (evidence redacted)")
    p.add_argument("-d", "--reports-dir", default=None, dest="reports_dir", metavar="DIR",
                   help="also write latest.json + latest.md into DIR (evidence redacted)")
    p.add_argument("--alert", action="store_true",
                   help="push the durable record in-pass: GitHub issue + Slack")
    # In-pass remediation.
    p.add_argument("--fix", action="store_true",
                   help="also remediate the scanned local repo(s) in the same pass (dry-run)")
    p.add_argument("--apply", action="store_true",
                   help="with --fix: write fixes (backed up to quarantine) and commit to a branch")
    p.add_argument("--pr", "--open-pr", action="store_true", dest="pr",
                   help="with --fix --apply: push a fix branch and open/update one PR per repo")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    paths = [*a.paths, *a.extra_paths]
    fix = a.fix or a.apply or a.pr          # --apply/--pr imply --fix
    return service.scan(a.config, local_only=a.local, paths=paths or None,
                        json_out=a.json, sarif_path=a.sarif, reports_dir=a.reports_dir,
                        alert=a.alert, fix=fix, apply=a.apply, open_pr=a.pr,
                        no_stream=a.no_stream)
