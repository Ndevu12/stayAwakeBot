#!/usr/bin/env python3
"""`saw audit` — credential + editor + runner-persistence + branch-protection hygiene audit."""
from __future__ import annotations

import argparse
import sys

from stayawake.bots.security import hygiene
from stayawake.cli.helptext import add_command
from stayawake.lib import auth
from stayawake.utils.render import term_width
from stayawake.utils.streaming import Streamer, status, stream_enabled
from stayawake.utils.terminal import supports_color


def register(sub) -> None:
    p = add_command(
        sub, "audit", aliases=["au"],
        help="hygiene + branch-protection audit",
        description=(
            "Audit local security hygiene: credential exposure, editor settings, host "
            "persistence and drop-artifacts, and optionally a repository's branch protection. "
            "Read-only. Every run ends with a rotation-safety verdict, and exit 3 means "
            "rotating a credential is not safe yet — active persistence was found, or the "
            "persistence surface could not be verified."),
        examples=[
            ("saw audit", "hygiene, persistence, rotation verdict"),
            ("saw audit --verify", "content-scan a weak ~/.node_modules"),
            ("saw audit --repo Ndevu12/strix -f", "also gate on branch protection"),
            ("saw audit; echo $?", "3 = rotation UNSAFE"),
        ])
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
    progress_on = stream_enabled(sys.stderr, force_off=a.no_stream)
    issues: list[hygiene.HygieneIssue] = []
    for label, check in hygiene.audit_checks(a.repo, token, a.branch,
                                             verify_artifacts=a.verify_artifacts):
        with status(f"checking {label}…", enabled=progress_on):
            issues += check()
    report = hygiene.render(issues, color=supports_color(sys.stdout), width=term_width())
    Streamer(enabled=stream_enabled(sys.stdout, force_off=a.no_stream)).line(report)
    # persistence surface that could not be verified withholds the all-clear → exit 3 ("rotation
    # unsafe / not verified"), regardless of -f, because rotating into a live wiper is data-loss. The
    # weaker hygiene warnings keep their opt-in gate (-f → 1). 3 is additive: every `rc==0`/`rc!=0`
    # consumer fails safe, and it is distinct from infected(1)/error(2). See docs/reference/exit-codes.md.
    if {i.id for i in issues} & hygiene.ROTATION_UNSAFE_IDS:
        return 3
    warnings = [i for i in issues if i.severity == "warning"]
    return 1 if (a.fail and warnings) else 0
