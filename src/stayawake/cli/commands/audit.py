#!/usr/bin/env python3
"""`saw audit` — credential + editor + runner-persistence + branch-protection hygiene audit."""
from __future__ import annotations

import argparse
import sys

from stayawake.bots.security import hygiene
from stayawake.core import auth
from stayawake.core.render import term_width
from stayawake.core.streaming import Streamer, status, stream_enabled
from stayawake.core.terminal import supports_color


def register(sub) -> None:
    p = sub.add_parser("audit", aliases=["au"], help="hygiene + branch-protection audit")
    p.add_argument("--repo", metavar="OWNER/NAME", default=None,
                   help="also audit this repo's branch protection (needs a token)")
    p.add_argument("-b", "--branch", default="main",
                   help="branch to check protection for (default: main)")
    p.add_argument("-f", "--fail", "--fail-on-issues", action="store_true", dest="fail",
                   help="exit non-zero if any warning-level issue is found")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable the per-check spinner and typewriter output (plain, instant)")
    p.add_argument("--verify", action="store_true", dest="verify_artifacts",
                   help="content-scan a lone weak host artifact (e.g. ~/.node_modules) to corroborate "
                        "it — slower; bounded and scans inside node_modules (does not touch saw scan)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    token, _ = auth.resolve_token()
    if a.repo and not token:
        print(auth.no_credential_hint("auditing branch protection") +
              " Skipping the branch-protection check.\n")
    # Stream like `saw scan`: a spinner over each probe's silent compute (some shell out to
    # launchctl/systemctl/the GitHub API), then the report typed out. Progress lives on stderr,
    # the report on stdout — each keys off its own tty-ness so a piped report stays clean.
    progress_on = stream_enabled(sys.stderr, force_off=a.no_stream)
    # Iterate hygiene.audit_checks() — the single composition site — never hand-assemble a subset.
    issues: list[hygiene.HygieneIssue] = []
    for label, check in hygiene.audit_checks(a.repo, token, a.branch,
                                             verify_artifacts=a.verify_artifacts):
        with status(f"checking {label}…", enabled=progress_on):
            issues += check()
    # Colour + wrap-width key off stdout the same way scan's TerminalSink does: colour only on a
    # real TTY (NO_COLOR / CI / pipe → plain), wrapped to the live terminal width (80 when piped).
    report = hygiene.render(issues, color=supports_color(sys.stdout), width=term_width())
    Streamer(enabled=stream_enabled(sys.stdout, force_off=a.no_stream)).line(report)
    warnings = [i for i in issues if i.severity == "warning"]
    return 1 if (a.fail and warnings) else 0
