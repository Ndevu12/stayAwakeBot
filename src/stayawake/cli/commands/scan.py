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
    p.add_argument("--no-advisories", action="store_true", dest="no_advisories",
                   help="suppress the dependency CVE-advisory section. A scan reports malware AND "
                        "known CVEs (from the offline DB) by default; advisories never change the "
                        "verdict/exit code, so this only quiets the output.")
    p.add_argument("-x", "--external", action="store_true", dest="external_audit",
                   help="also run INSTALLED external auditors (osv-scanner, …) and fold their vulns "
                        "into the advisory tier. OPT-IN — this leaves the offline sandbox: it spawns "
                        "subprocesses and a tool may send your dependency list to its own servers. "
                        "Absent tools are skipped; never changes the verdict/exit code.")
    p.add_argument("--require-db", action="store_true", dest="require_db",
                   help="fail (exit 2) if the advisory DB is absent or fails its integrity check, "
                        "instead of falling back to the inline malware seed — for CI gates that must "
                        "not silently lose coverage. Default is fail-open (degrade to the seed).")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress/typewriter output (plain, instant lines)")
    p.add_argument("--pager", action="store_true", dest="pager",
                   help="page the report through $PAGER (less); off by default — the report "
                        "prints straight through and a big sweep's full detail goes to a file")
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
                        alert=a.alert, no_stream=a.no_stream, pager=a.pager,
                        no_advisories=a.no_advisories, external_audit=a.external_audit,
                        require_db=a.require_db)
