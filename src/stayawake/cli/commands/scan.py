#!/usr/bin/env python3
"""`saw scan` — hunt supply-chain worms (READ-ONLY). Routes to security.service.scan.

Terminal-first: by default the result is rendered to the terminal and NOTHING is written to
disk. The verdict is the exit code (0 clean / 1 infected), unconditionally. Scope is LOCAL
by default (given paths / configured globs / the current repo); `--remote` scans the
configured GitHub targets instead. Persisting or alerting is opt-in: --json (machine
stdout), --sarif FILE, -d DIR (both redacted), --alert (GitHub issue + Slack). Remediation
lives in `saw fix`, never here.
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import service


def register(sub) -> None:
    p = sub.add_parser("scan", aliases=["s", "sc"], help="hunt supply-chain worms (read-only)")
    p.add_argument("paths", nargs="*", metavar="PATHS",
                   help="repo/dir paths to scan. Omit to scan configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional path to scan (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("-r", "--remote", action="store_true",
                   help="scan the configured GitHub targets instead of local repos")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress/typewriter output (plain, instant lines)")
    # Opt-in output surfaces (terminal-first: none of these is on by default).
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON to stdout (full evidence; progress on stderr)")
    p.add_argument("--sarif", default=None, metavar="FILE",
                   help="write a SARIF 2.1.0 report to FILE for code-scanning (evidence redacted)")
    p.add_argument("-d", "--reports-dir", default=None, dest="reports_dir", metavar="DIR",
                   help="also write latest.json + latest.md into DIR (evidence redacted)")
    p.add_argument("--alert", action="store_true",
                   help="push the durable record in-pass: GitHub issue + Slack")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    paths = [*a.paths, *a.extra_paths]
    return service.scan(a.config, remote=a.remote, paths=paths or None,
                        json_out=a.json, sarif_path=a.sarif, reports_dir=a.reports_dir,
                        alert=a.alert, no_stream=a.no_stream)
