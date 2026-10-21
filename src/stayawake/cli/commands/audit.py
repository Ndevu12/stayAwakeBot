#!/usr/bin/env python3
"""`saw audit` — credential + editor + runner-persistence + branch-protection hygiene audit."""
from __future__ import annotations

import argparse
import json
import sys

from stayawake.bots.security import hygiene
from stayawake.cli.helptext import add_command
from stayawake.lib import auth
from stayawake.utils.json_documents import versioned
from stayawake.utils.render import term_width
from stayawake.utils.streaming import Streamer, status, stream_enabled
from stayawake.utils.terminal import supports_color
from stayawake.utils import exitcodes
from stayawake.cli.argtypes import no_stream_requested


def register(sub) -> None:
    p = add_command(
        sub, "audit", aliases=["au"],
        help="hygiene + branch-protection audit",
        description=(
            "Audit this machine's security posture, and optionally a repository's branch "
            "protection. Read-only. Every run ends with a rotation-safety verdict: rotating a "
            "credential is safe only once no persistence is found and the whole start-up "
            "surface was read."),
        examples=[
            ("saw audit", "ends with the rotation-safety verdict"),
            ("saw audit --json", "the same verdict, for a program to read"),
            ("saw audit --verify", "content-scan what a weak signal names"),
            ("saw audit --repo your-org/repo -f", "also gate on branch protection"),
        ])
    p.add_argument("--repo", metavar="OWNER/NAME", default=None,
                   help="also audit this repo's branch protection (needs a token)")
    p.add_argument("-b", "--branch", default="main",
                   help="branch to check protection for (default: main)")
    p.add_argument("-f", "--fail", "--fail-on-issues", action="store_true", dest="fail",
                   help="exit non-zero if any warning-level issue is found, or if --repo could not "
                        "check whether the branch requires the worm gate")
    p.add_argument("--verify", action="store_true", dest="verify_artifacts",
                   help="also read the files a finding points to, to confirm it (slower)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    token, _ = auth.resolve_token()
    if a.repo and not token:
        print(auth.no_credential_hint("auditing branch protection") +
              " Skipping the branch-protection check.\n",
              file=sys.stderr if a.json else sys.stdout)
    progress_on = stream_enabled(sys.stderr, force_off=no_stream_requested(a))
    outcomes: list[hygiene.CheckOutcome] = []
    for label, check in hygiene.audit_checks(a.repo, token, a.branch,
                                             verify_artifacts=a.verify_artifacts):
        with status(f"checking {label}…", enabled=progress_on):
            outcomes.append(hygiene.run_check(label, check))
    issues = [i for o in outcomes for i in o.issues]
    if a.json:
        print(json.dumps(versioned("audit", hygiene.as_document(outcomes)), indent=2))
    else:
        report = hygiene.render(issues, color=supports_color(sys.stdout), width=term_width(),
                                content_scanned=a.verify_artifacts)
        Streamer(enabled=stream_enabled(sys.stdout, force_off=no_stream_requested(a))).line(report)
    # persistence surface that could not be verified withholds the all-clear → exit 3 ("rotation
    # unsafe / not verified"), regardless of -f, because rotating into a live wiper is data-loss. The
    # weaker hygiene warnings keep their opt-in gate (-f → 1). 3 is additive: every `rc==0`/`rc!=0`
    # consumer fails safe, and it is distinct from infected(1)/error(2).
    if {i.id for i in issues} & hygiene.ROTATION_UNSAFE_IDS:
        return exitcodes.ROTATION_UNSAFE
    # A probe whose own discriminator failed did not answer, and an unanswered probe is the
    # documented meaning of 2 — "a run that could not complete". It is checked AFTER 3 because a
    # blocked probe is a gap in what the run covered, while 3 is a hazard in what it found.
    if any(o.state == hygiene.BLOCKED for o in outcomes):
        return exitcodes.INCOMPLETE
    gating = [i for i in issues if i.severity == "warning" or i.id in hygiene.UNCHECKED_GATE_IDS]
    return 1 if (a.fail and gating) else 0
