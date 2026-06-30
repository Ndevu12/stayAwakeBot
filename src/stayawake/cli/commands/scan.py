#!/usr/bin/env python3
"""`saw scan` — hunt supply-chain worms (READ-ONLY). Routes to security.service.scan.

Terminal-first: by default the result is rendered to the terminal and NOTHING is written to
disk. The verdict is the exit code (0 clean / 1 infected), unconditionally. Scope is LOCAL by
default (given paths / configured globs / the current repo); `--remote` (or naming `--user`/
`--org`) scans GitHub repos instead — ad-hoc selectors, else configured targets, else your own
repos. Persisting/alerting is opt-in: --json, --sarif FILE, -d DIR (redacted), --alert.
Remediation lives in `saw fix`, never here.
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import service


def register(sub) -> None:
    p = sub.add_parser("scan", aliases=["s", "sc"], help="hunt supply-chain worms (read-only)")
    p.add_argument("paths", nargs="*", metavar="TARGETS",
                   help="local repo/dir paths — or, with --remote, owner/repo slugs. "
                        "Omit to scan configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional target (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("-r", "--remote", action="store_true",
                   help="scan GitHub repos instead of local: ad-hoc --user/--org/owner-repo, "
                        "else configured targets, else your own repos")
    p.add_argument("--user", action="append", default=[], metavar="USER",
                   help="scan this GitHub user's repos (repeatable; implies --remote)")
    p.add_argument("--org", action="append", default=[], metavar="ORG",
                   help="scan this GitHub org's repos (repeatable; implies --remote)")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress/typewriter output (plain, instant lines)")
    p.add_argument("--no-pager", action="store_true", dest="no_pager",
                   help="don't page a long report through $PAGER — print it straight through")
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
    positionals = [*a.paths, *a.extra_paths]
    remote = a.remote or bool(a.user) or bool(a.org)   # naming a GitHub account implies --remote
    return service.scan(a.config, remote=remote,
                        paths=None if remote else (positionals or None),
                        slugs=(positionals or None) if remote else None,
                        users=a.user or None, orgs=a.org or None,
                        json_out=a.json, sarif_path=a.sarif, reports_dir=a.reports_dir,
                        alert=a.alert, no_stream=a.no_stream, no_pager=a.no_pager)
