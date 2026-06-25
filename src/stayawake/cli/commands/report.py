#!/usr/bin/env python3
"""`saw report` — render the latest scan into a report. Routes to reporter.generate."""
from __future__ import annotations

import argparse

from stayawake.bots.security import reporter
from stayawake.cli._meta import DEFAULT_LATEST


def register(sub) -> None:
    p = sub.add_parser("report", aliases=["rep", "re"], help="render latest security report")
    p.add_argument("-l", "--latest", default=DEFAULT_LATEST,
                   help=f"results JSON to render (default: {DEFAULT_LATEST})")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    reporter.generate(latest_path=a.latest)
    return 0
