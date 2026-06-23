#!/usr/bin/env python3
"""Security orchestration: resolve targets → scan → write reports.

Single responsibility: wire the security stages together. Detection lives in the
matchers; this just gathers targets and persists results. Never executes scanned
code; remote repos are cloned read-only into sandboxes and removed after.
"""
from __future__ import annotations

import os
from pathlib import Path

from stayawake.core.config import load_yaml
from stayawake.core.io import write_json
from stayawake.core.timeutil import now_iso
from stayawake.core.adapters import github_api
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.models import ScanResult
from stayawake.bots.security.targets import ScanOptions, LocalRepoTarget, RemoteRepoTarget

REPORTS_DIR = Path("reports/security")


def _options(settings: dict) -> ScanOptions:
    base = ScanOptions()
    return ScanOptions(
        exclude_dirs=set(settings.get("exclude_dirs", base.exclude_dirs)),
        max_file_bytes=int(settings.get("max_file_bytes", base.max_file_bytes)),
        remote_clone_depth=int(settings.get("remote_clone_depth", base.remote_clone_depth)),
    )


def discover_local_repos(patterns: list[str], opts: ScanOptions) -> list[Path]:
    repos: list[Path] = []
    seen: set[str] = set()
    for pat in patterns or []:
        root = Path(os.path.expanduser(pat).split("*", 1)[0] or "/")
        if not root.exists():
            root = root.parent
        if not root.exists():
            continue
        for dirpath, dirnames, _ in os.walk(root):
            if (Path(dirpath) / ".git").exists():
                rp = Path(dirpath).resolve()
                if str(rp) not in seen:
                    seen.add(str(rp))
                    repos.append(rp)
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in opts.exclude_dirs]
    return repos


def _render_markdown(payload: dict) -> str:
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
            loc = f["path"] + (f":{f['line']}" if f.get("line") else "")
            out.append(f"- **[{f['severity']}]** `{f['signature_id']}` — {loc}")
            out.append(f"  - {f['description']}")
            if f.get("evidence"):
                out.append(f"  - evidence: `{f['evidence']}`")
        out.append("")
    if not any_f:
        out.append("_No findings — all scanned targets are clean._")
    return "\n".join(out) + "\n"


def _resolve_remote(cfg: dict, opts: ScanOptions):
    gconf = cfg.get("targets", {}).get("github", {}) or {}
    token = os.environ.get("GH_SECURITY_TOKEN") or os.environ.get("GITHUB_TOKEN")
    slugs: list[str] = []
    for kind in ("users", "orgs"):
        for acct in gconf.get(kind, []) or []:
            slugs += github_api.list_repos(acct, kind, token,
                                           gconf.get("include_forks", False),
                                           gconf.get("include_archived", False))
    return sorted(set(slugs)), token


def scan(config_path: str = "config/security.yml", local_only: bool = False,
         fail_on_findings: bool = False) -> int:
    cfg = load_yaml(config_path)
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])

    results: list[ScanResult] = []
    for repo in discover_local_repos(cfg.get("targets", {}).get("local", []), opts):
        display = str(repo).replace(os.path.expanduser("~"), "~")
        with LocalRepoTarget(repo, display, opts) as t:
            results.append(scan_target(t, sigs, allowlist))

    if not local_only:
        slugs, token = _resolve_remote(cfg, opts)
        for slug in slugs:
            rt = RemoteRepoTarget(slug, opts, token)
            try:
                results.append(scan_target(rt, sigs, allowlist) if rt.clone()
                               else ScanResult(target=slug, source="remote", error="clone failed"))
            finally:
                rt.cleanup()

    payload = {
        "generated_at": now_iso(),
        "summary": {
            "targets": len(results),
            "infected": sum(1 for r in results if r.infected),
            "findings": sum(len(r.findings) for r in results),
            "critical": sum(1 for r in results for f in r.findings if f.severity.label() == "critical"),
            "high": sum(1 for r in results for f in r.findings if f.severity.label() == "high"),
        },
        "any_infected": any(r.infected for r in results),
        "results": [r.to_dict() for r in results],
    }
    write_json(REPORTS_DIR / "latest.json", payload)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "latest.md").write_text(_render_markdown(payload), encoding="utf-8")

    s = payload["summary"]
    print(f"Scanned {s['targets']} target(s): {s['infected']} infected, "
          f"{s['findings']} findings ({s['critical']} critical, {s['high']} high)")
    for r in results:
        tag = "INFECTED" if r.infected else ("ERROR" if r.error else "clean")
        print(f"  [{tag:8}] {r.target}  ({len(r.findings)} findings)")

    return 1 if (fail_on_findings and payload["any_infected"]) else 0
