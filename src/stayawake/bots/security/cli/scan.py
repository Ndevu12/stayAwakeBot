#!/usr/bin/env python3
"""Entrypoint: security scan. `python -m security.cli.scan`."""
from __future__ import annotations

import argparse
import sys

from stayawake.bots.security import service


def main() -> None:
    p = argparse.ArgumentParser(description="StayAwakeBot security scanner")
    p.add_argument("paths", nargs="*",
                   help="repo or directory paths to scan (ad-hoc, local-only). If omitted "
                        "and nothing is configured, scans the current repository.")
    p.add_argument("--path", action="append", default=[], dest="extra_paths", metavar="PATH",
                   help="additional path to scan (repeatable); same effect as a positional path")
    p.add_argument("--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("--local-only", action="store_true", help="skip remote GitHub targets")
    p.add_argument("--fail-on-findings", action="store_true",
                   help="exit non-zero if any infected target (for CI gating)")
    p.add_argument("--reports-dir", default=None,
                   help="where to write reports (default: reports/security); use a scratch "
                        "dir to avoid touching committed reports")
    a = p.parse_args()
    paths = [*a.paths, *a.extra_paths]
    sys.exit(service.scan(a.config, a.local_only, a.fail_on_findings, a.reports_dir,
                          paths or None))


if __name__ == "__main__":
    main()
