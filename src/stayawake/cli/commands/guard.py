#!/usr/bin/env python3
"""`saw guard` — install & verify the Strix CI gate on a repo (#1229).

This slice ships `saw guard check` (read-only). `saw guard setup` (writing/updating the workflow)
builds on the same detection and follows.
"""
from __future__ import annotations

import argparse
import sys

from stayawake.core import auth
from stayawake.core.streaming import Streamer, stream_enabled
from stayawake.core.terminal import supports_color


def register(sub) -> None:
    p = sub.add_parser("guard", aliases=["gd"],
                       help="install & verify the Strix security-scan CI gate on a repo")
    p.set_defaults(func=lambda a: (p.print_help() or 0))
    gsub = p.add_subparsers(dest="guard_command", metavar="<subcommand>")

    ck = gsub.add_parser(
        "check", help="check the Strix gate: present, SHA-pinned, fresh, and required",
        description="Detect the Strix gate by its `uses: Ndevu12/strix@…` action reference (not by "
                    "filename), grade the pin (a commit SHA is best), report whether it is behind the "
                    "latest Strix release, and — for a remote repo — whether branch protection "
                    "requires it. Read-only; never runs the repo's code.")
    ck.add_argument("--repo", metavar="OWNER/NAME", default=None,
                    help="check a remote GitHub repo instead of the local working tree")
    ck.add_argument("-b", "--branch", default="main",
                    help="branch whose protection must require the gate (default: main)")
    ck.add_argument("-f", "--fail", action="store_true", dest="fail",
                    help="exit non-zero when the gate is absent, unpinned, stale, or not required")
    ck.add_argument("--no-stream", action="store_true", dest="no_stream",
                    help="disable the typewriter output (plain, instant)")
    ck.set_defaults(func=run_check)


def run_check(a: argparse.Namespace) -> int:
    from stayawake.bots.security import guard   # lazy: pull yaml/API in only when the command runs

    token = None
    if a.repo:
        token, _ = auth.resolve_token()
        if not token:
            print(auth.no_credential_hint("checking a remote repo's gate") +
                  " (branch-protection + freshness checks need it)\n", file=sys.stderr)

    status = guard.check(slug=a.repo, branch=a.branch, token=token)
    Streamer(enabled=stream_enabled(sys.stdout, force_off=a.no_stream)).line(
        guard.render(status, color=supports_color(sys.stdout)))
    return 1 if (a.fail and not status.healthy) else 0
