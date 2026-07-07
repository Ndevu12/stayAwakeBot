#!/usr/bin/env python3
"""`saw db` — manage the offline advisory database.

`saw db update` is the scanner's only network operation: it bulk-downloads the OSV
malicious-package corpus into a local cache so scans can match dynamically while staying offline.
The download names only the ecosystem, never a package, so it can't leak your dependency graph.
"""
from __future__ import annotations

import argparse
import sys

from stayawake.core.streaming import Streamer, status, stream_enabled


def register(sub) -> None:
    p = sub.add_parser("db", help="manage the offline advisory database")
    p.set_defaults(func=lambda a: (p.print_help() or 0))
    dbsub = p.add_subparsers(dest="db_command", metavar="<subcommand>")

    up = dbsub.add_parser(
        "update", help="download/refresh the offline malicious-package advisory DB",
        description="Fetch the OSV malicious-package corpus (OpenSSF / GitHub Advisories / OSV.dev) "
                    "into the local cache. Names only the ecosystem — never your packages.")
    up.add_argument("-e", "--ecosystem", action="append", dest="ecosystems", metavar="ECO",
                    help="limit to an ecosystem (repeatable); default: all supported")
    up.add_argument("--cache-dir", default=None,
                    help="advisory cache location (default: ~/.cache/saw/advisories)")
    up.add_argument("--no-stream", action="store_true", dest="no_stream",
                    help="disable the per-ecosystem spinner and typewriter output")
    up.set_defaults(func=run_update)


def run_update(a: argparse.Namespace) -> int:
    # Imported here (not at module load) so the CLI stays light and the network/zip machinery is
    # only pulled in when this command actually runs.
    from stayawake.bots.security.dependencies import db

    progress_on = stream_enabled(sys.stderr, force_off=a.no_stream)
    try:
        ecosystems = db.resolved_ecosystems(a.ecosystems)
        results = []
        for eco in ecosystems:
            with status(f"updating {eco} advisories…", enabled=progress_on):
                results.append(db.update_ecosystem(eco, a.cache_dir))
        manifest = db.write_manifest(a.cache_dir, results)
    except ValueError as e:                      # unsupported ecosystem — user error, not a crash
        print(f"saw db update: {e}", file=sys.stderr)
        return 2
    except Exception as e:                        # noqa: BLE001 — network/parse failure → report, exit 1
        print(f"saw db update failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    total = sum(r["count"] for r in results)
    lines = ["Advisory database updated.",
             *(f"  {r['ecosystem']:<10} {r['count']:>6} malicious packages" for r in results),
             f"  {'total':<10} {total:>6}",
             f"cache: {db.default_cache_dir() if not a.cache_dir else a.cache_dir}"]
    Streamer(enabled=stream_enabled(sys.stdout, force_off=a.no_stream)).line("\n".join(lines))
    return 0
