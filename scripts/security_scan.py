#!/usr/bin/env python3
"""StayAwakeBot Security Sentinel — scanner CLI (Phase 1: detect + report).

Resolves local and remote targets from config/security.yml, scans each with the
signature engine, and writes reports/security/latest.json plus a markdown report.
Detection only — it never executes scanned code and never modifies target repos.

Usage:
  python -m scripts.security_scan --config config/security.yml
  python -m scripts.security_scan --local-only --fail-on-findings
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow both `python -m scripts.security_scan` and direct execution.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from helpers.common.io import utc_iso_now, write_json_atomic  # noqa: E402
from helpers.common import github as gh  # noqa: E402
from helpers.security.signatures import load_signatures  # noqa: E402
from helpers.security.scanner import scan_target  # noqa: E402
from helpers.security.targets import (  # noqa: E402
    ScanOptions, LocalRepoTarget, RemoteRepoTarget,
)

REPORTS_DIR = Path("reports/security")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="StayAwakeBot security scanner")
    p.add_argument("--config", default="config/security.yml")
    p.add_argument("--local-only", action="store_true", help="skip remote GitHub targets")
    p.add_argument("--fail-on-findings", action="store_true",
                   help="exit non-zero if any infected target (for CI gating)")
    p.add_argument("--min-severity", default=None,
                   help="only count findings at/above this severity for exit code")
    return p.parse_args()


def discover_local_repos(patterns: list[str], opts: ScanOptions) -> list[Path]:
    """Find git repositories beneath each pattern's non-glob prefix."""
    repos: list[Path] = []
    seen: set[str] = set()
    for pat in patterns or []:
        expanded = os.path.expanduser(pat)
        root = expanded.split("*", 1)[0] or "/"
        root_path = Path(root)
        if not root_path.exists():
            root_path = root_path.parent
        if not root_path.exists():
            continue
        for dirpath, dirnames, _ in os.walk(root_path):
            if ".git" in dirnames or (Path(dirpath) / ".git").exists():
                rp = Path(dirpath).resolve()
                if str(rp) not in seen:
                    seen.add(str(rp))
                    repos.append(rp)
                dirnames[:] = []  # don't descend into a repo
                continue
            dirnames[:] = [d for d in dirnames if d not in opts.exclude_dirs]
    return repos


def build_options(settings: dict) -> ScanOptions:
    return ScanOptions(
        exclude_dirs=set(settings.get("exclude_dirs", ScanOptions().exclude_dirs)),
        max_file_bytes=int(settings.get("max_file_bytes", 2_000_000)),
        remote_clone_depth=int(settings.get("remote_clone_depth", 50)),
    )


def render_markdown(payload: dict) -> str:
    s = payload["summary"]
    out = [f"# Security scan — {payload['generated_at']}", "",
           f"**{s['targets']} targets** · {s['infected']} infected · "
           f"{s['findings']} findings ({s['critical']} critical, {s['high']} high)", "",
           "| Target | Source | Status | Findings | Top severity |",
           "|--------|--------|--------|----------|--------------|"]
    for r in payload["results"]:
        status = "❌ INFECTED" if r["infected"] else ("⚠️ error" if r["error"] else "✅ clean")
        out.append(f"| {r['target']} | {r['source']} | {status} | "
                   f"{r['summary']['total']} | {r['summary']['max_severity'] or '—'} |")
    out += ["", "## Findings", ""]
    any_f = False
    for r in payload["results"]:
        if not r["findings"]:
            continue
        any_f = True
        out.append(f"### {r['target']}")
        for f in r["findings"]:
            loc = f"{f['path']}" + (f":{f['line']}" if f.get("line") else "")
            out.append(f"- **[{f['severity']}]** `{f['signature_id']}` — {loc}")
            out.append(f"  - {f['description']}")
            if f.get("evidence"):
                out.append(f"  - evidence: `{f['evidence']}`")
        out.append("")
    if not any_f:
        out.append("_No findings — all scanned targets are clean._")
    return "\n".join(out) + "\n"


def main() -> None:
    args = parse_args()
    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {}
    settings = cfg.get("settings", {})
    opts = build_options(settings)
    sigs = load_signatures(settings.get("signatures_path", "config/security_signatures.yml"))
    allowlist = cfg.get("allowlist", [])

    results = []

    # ── Local targets ──
    for repo in discover_local_repos(cfg.get("targets", {}).get("local", []), opts):
        with LocalRepoTarget(repo, str(repo).replace(os.path.expanduser("~"), "~"), opts) as t:
            results.append(scan_target(t, sigs, allowlist))

    # ── Remote targets ──
    if not args.local_only:
        gconf = cfg.get("targets", {}).get("github", {}) or {}
        token = os.environ.get("GH_SECURITY_TOKEN") or os.environ.get("GITHUB_TOKEN")
        slugs: list[str] = []
        for kind in ("users", "orgs"):
            for acct in gconf.get(kind, []) or []:
                slugs += gh.list_repos(acct, kind, token,
                                       gconf.get("include_forks", False),
                                       gconf.get("include_archived", False))
        for slug in sorted(set(slugs)):
            rt = RemoteRepoTarget(slug, opts, token)
            try:
                if rt.clone():
                    results.append(scan_target(rt, sigs, allowlist))
                else:
                    from helpers.security.findings import ScanResult
                    results.append(ScanResult(target=slug, source="remote",
                                              error="clone failed"))
            finally:
                rt.cleanup()

    # ── Aggregate ──
    payload_results = [r.to_dict() for r in results]
    total_findings = sum(len(r.findings) for r in results)
    crit = sum(1 for r in results for f in r.findings if f.severity.label() == "critical")
    high = sum(1 for r in results for f in r.findings if f.severity.label() == "high")
    payload = {
        "generated_at": utc_iso_now(),
        "summary": {
            "targets": len(results),
            "infected": sum(1 for r in results if r.infected),
            "findings": total_findings,
            "critical": crit,
            "high": high,
        },
        "any_infected": any(r.infected for r in results),
        "results": payload_results,
    }
    write_json_atomic(REPORTS_DIR / "latest.json", payload)
    (REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "latest.md").write_text(render_markdown(payload), encoding="utf-8")

    # ── Console summary ──
    print(f"Scanned {payload['summary']['targets']} target(s): "
          f"{payload['summary']['infected']} infected, {total_findings} findings "
          f"({crit} critical, {high} high)")
    for r in results:
        tag = "INFECTED" if r.infected else ("ERROR" if r.error else "clean")
        print(f"  [{tag:8}] {r.target}  ({len(r.findings)} findings)")

    if args.fail_on_findings and payload["any_infected"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
