"""`saw serve` — stay running and answer scan and audit questions."""
from __future__ import annotations

import argparse
import sys

from stayawake.cli.helptext import add_command
from stayawake.utils import exitcodes


def register(sub) -> None:
    p = add_command(
        sub, "serve", stream=False,
        help="stay running and answer scan and audit questions",
        description=(
            "Stay running and answer a scan, a scan of named files, a verdict, and an audit. "
            "The answers are the same JSON documents as saw scan --json and saw audit --json. "
            "A later question about a folder that has not changed reuses that result. A question "
            "that does not finish is not verified. This does not change files."),
        examples=[
            ("saw serve --stdio", "for an editor that keeps one saw running"),
        ])
    p.add_argument("--stdio", action="store_true",
                   help="answer on standard input and output")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    if not a.stdio:
        print("saw serve answers on its standard input. Pass --stdio. The answer is not verified.",
              file=sys.stderr)
        return exitcodes.INCOMPLETE
    from stayawake.bots.mcp.worker import serve

    return serve(sys.stdin, sys.stdout)
