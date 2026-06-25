#!/usr/bin/env python3
"""`saw doctor` — self-check the install and credentials.

A dispatcher-owned command, so it honours --json / -q. It also reports that the
health entry points are installed even though they are not `saw` subcommands.
"""
from __future__ import annotations

import argparse
import json
import shutil

from stayawake.cli._meta import __version__
from stayawake.core import auth


def register(sub) -> None:
    p = sub.add_parser("doctor", aliases=["d", "doc"], help="self-check install + credentials")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-q", "--quiet", action="store_true", help="print only problems")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    saw_path = shutil.which("saw") or shutil.which("stayawake")
    _, source = auth.resolve_token()
    health = shutil.which("stayawake-health-check")

    if a.json:
        print(json.dumps({
            "saw_on_path": saw_path,
            "credential": source,
            "health_scripts_installed": bool(health),
            "version": __version__,
        }, indent=2))
        return 0

    def mark(ok: bool) -> str:
        return "✓" if ok else "✗"

    lines = [
        f"{mark(bool(saw_path))} saw resolves to: {saw_path or 'NOT FOUND on PATH'}",
        (f"✓ GitHub credential: {source}" if source else
         "• no GitHub credential (public scans + local audit still work; needed "
         "for private repos and remote fix PRs)"),
        f"{mark(bool(health))} health entry points installed (remote-only, not saw "
        f"subcommands): {'yes' if health else 'no'}",
        f"• version: {__version__}",
    ]
    if a.quiet:
        problems = [ln for ln in lines if ln.startswith("✗")]
        print("\n".join(problems) if problems else "ok")
    else:
        print("\n".join(lines))
    return 0
