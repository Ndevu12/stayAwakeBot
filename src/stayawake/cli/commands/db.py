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

    st = dbsub.add_parser(
        "status", help="show the advisory DB's snapshot, age, counts and integrity",
        description="Report the offline advisory cache: snapshot fingerprint, age, per-ecosystem "
                    "counts, and a content-hash integrity check. Exits non-zero if the DB is absent, "
                    "fails integrity, is older than --max-age-days, or doesn't match --require-snapshot "
                    "— so CI can pin a reproducible DB.")
    st.add_argument("--cache-dir", default=None, help="advisory cache location")
    st.add_argument("--require-snapshot", metavar="DIGEST", default=None,
                    help="exit non-zero unless the DB's snapshot equals DIGEST (pin for reproducible CI)")
    st.add_argument("--max-age-days", type=int, default=None, metavar="N",
                    help="exit non-zero if the DB is older than N days")
    st.set_defaults(func=run_status)


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

    mal = sum(r["malicious"] for r in results)
    vuln = sum(r["vulnerabilities"] for r in results)
    lines = ["Advisory database updated.",
             *(f"  {r['ecosystem']:<10} {r['malicious']:>6} malicious · "
               f"{r['vulnerabilities']:>6} vulnerabilities" for r in results),
             f"  {'total':<10} {mal:>6} malicious · {vuln:>6} vulnerabilities",
             "  (malware gates the verdict; vulnerabilities show as advisories in `saw scan` — "
             "`--no-advisories` to hide, `--external` to also run installed auditors)",
             f"cache: {db.default_cache_dir() if not a.cache_dir else a.cache_dir}"]
    Streamer(enabled=stream_enabled(sys.stdout, force_off=a.no_stream)).line("\n".join(lines))
    return 0


def run_status(a: argparse.Namespace) -> int:
    from stayawake.bots.security.dependencies import db

    s = db.cache_status(a.cache_dir)
    if not s["present"]:
        print(f"Advisory DB: not found at {s['cache_dir']}\n"
              "  run `saw db update` — scans fall back to the inline malware seed until then.")
        return 1

    age = s["age_days"]
    schema_ok = s.get("schema_compatible", True)
    # Distinguish a benign version skew from tampering: an older-format cache is not "FAILED".
    if not schema_ok:
        integrity = f"older format (schema {s['schema']}) — run `saw db update`"
    elif s["integrity_ok"]:
        integrity = "OK"
    else:
        integrity = "FAILED: " + ", ".join(s["mismatches"])
    lines = [f"Advisory DB @ {s['cache_dir']}",
             f"  snapshot   {s['snapshot'] or '(legacy — re-run db update)'}",
             f"  generated  {s['generated_at'] or '?'}"
             + (f"  ({age} day(s) ago)" if age is not None else ""),
             f"  integrity  {integrity}",
             f"  totals     {s['total_malicious']} malicious · {s['total_vulnerabilities']} vulnerabilities",
             *(f"    {eco:<10} {c['malicious']:>7} malicious · {c['vulnerabilities']:>7} vulnerabilities"
               for eco, c in s["ecosystems"].items())]
    print("\n".join(lines))

    # CI gates — each prints why it failed and returns non-zero.
    rc = 0
    if not schema_ok:
        # Unusable cache (falls back to the inline seed), but NOT a security incident.
        print(f"✗ advisory DB is an older format (schema {s['schema']}) — run `saw db update`.",
              file=sys.stderr)
        rc = 2
    elif not s["integrity_ok"]:
        print("✗ integrity check failed — the cache was corrupted or tampered.", file=sys.stderr)
        rc = 2
    if a.require_snapshot and s["snapshot"] != a.require_snapshot:
        print(f"✗ snapshot {s['snapshot']} != required {a.require_snapshot}.", file=sys.stderr)
        rc = rc or 3
    if a.max_age_days is not None:
        if age is None:
            # Freshness was explicitly requested but can't be verified (legacy/missing/invalid
            # generated_at) → fail CLOSED, never pass a DB of unknown age.
            print("✗ DB age is unknown (missing/invalid generated_at) — cannot honor "
                  "--max-age-days; run `saw db update`.", file=sys.stderr)
            rc = rc or 3
        elif age > a.max_age_days:
            print(f"✗ DB is {age} day(s) old (> {a.max_age_days}).", file=sys.stderr)
            rc = rc or 3
    return rc
