#!/usr/bin/env python3
"""`saw run` — the scan -> report -> alert pipeline in one pass.

Reuses `scan`'s arguments and threads the report path internally, so the user never
names the intermediate latest.json. The reports dir is resolved ONCE (honouring -d,
then STAYAWAKE_REPORTS_DIR, then the default) and reused for the scan and for the
report/alert reads, so the three stages always agree on where latest.json lives.
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import alerter, reporter, service
from stayawake.bots.security.service import REPORTS_DIR
from stayawake.cli.commands.scan import add_scan_args
from stayawake.core.io import resolve_reports_dir


def register(sub) -> None:
    p = sub.add_parser("run", aliases=["ru"], help="scan -> report -> alert pipeline")
    add_scan_args(p)
    p.add_argument("-f", "--fail", "--fail-on-findings", action="store_true", dest="fail",
                   help="exit non-zero if any target is infected")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    reports_dir = resolve_reports_dir(a.reports_dir, default=REPORTS_DIR)
    paths = [*a.paths, *a.extra_paths]
    code = service.scan(a.config, a.local, a.fail, reports_dir, paths or None,
                        no_stream=a.no_stream)
    latest = str(reports_dir / "latest.json")
    reporter.generate(latest_path=latest)
    alerter.run(latest_path=latest)
    return code
