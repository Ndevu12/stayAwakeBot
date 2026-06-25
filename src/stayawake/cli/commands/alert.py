#!/usr/bin/env python3
"""`saw alert` — emit Slack / GitHub alerts for the latest scan. Routes to alerter.run."""
from __future__ import annotations

import argparse

from stayawake.bots.security import alerter
from stayawake.cli._meta import DEFAULT_LATEST


def register(sub) -> None:
    p = sub.add_parser("alert", aliases=["al"], help="emit security alerts")
    p.add_argument("-l", "--latest", default=DEFAULT_LATEST,
                   help=f"results JSON to alert on (default: {DEFAULT_LATEST})")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    alerter.run(latest_path=a.latest)
    return 0
