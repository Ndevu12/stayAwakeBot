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
from stayawake.core.io import write_json, resolve_reports_dir
from stayawake.core.timeutil import now_iso
from stayawake.core.adapters import github_api
from stayawake.core import auth
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.models import ScanResult
from stayawake.bots.security.targets import ScanOptions, LocalRepoTarget, RemoteRepoTarget

REPORTS_DIR = Path("reports/security")
DEFAULT_CONFIG = "config/security.yml"


def _read_config(config_path: str | None) -> dict:
    """Load the scan config. When `config_path` is None we use the default file if it
    exists, else an empty config — so a bare `stayawake-security-scan` in any repo
    works without a config. An explicitly-given path that is missing is an error."""
    if config_path is None:
        p = Path(DEFAULT_CONFIG)
        return load_yaml(p) if p.exists() else {}
    return load_yaml(config_path)


def _enclosing_repo_root(start: Path | None = None) -> Path:
    """Nearest ancestor of `start` (default: CWD) that contains a .git, else `start`.
    Lets a bare invocation default to 'scan the repo I'm standing in', even from a
    subdirectory."""
    start = (start or Path.cwd()).resolve()
    for d in (start, *start.parents):
        if (d / ".git").exists():
            return d
    return start


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
           f"{s.get('suspicious', 0)} suspicious · "
           f"{s['findings']} findings ({s['critical']} critical, {s['high']} high)", "",
           "_Verdict: **infected** = a confirmed (high-confidence) signature matched; "
           "**suspicious** = only heuristic match(es) that benign code can also produce — "
           "review, not asserted as malware._", "",
           "| Target | Source | Status | Findings | Top severity |",
           "|--------|--------|--------|----------|--------------|"]
    for r in payload["results"]:
        status = ("❌ INFECTED" if r["infected"]
                  else "🟡 SUSPICIOUS" if r.get("suspicious")
                  else "⚠️ error" if r["error"] else "✅ clean")
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
            out.append(f"- **[{f['severity']} · {f.get('confidence', 'confirmed')}]** "
                       f"`{f['signature_id']}` — {loc}")
            out.append(f"  - {f['description']}")
            if f.get("evidence"):
                out.append(f"  - evidence: `{f['evidence']}`")
        out.append("")
    if not any_f:
        out.append("_No findings — all scanned targets are clean._")
    return "\n".join(out) + "\n"


def _resolve_remote(cfg: dict, opts: ScanOptions):
    gconf = cfg.get("targets", {}).get("github", {}) or {}
    token, source = auth.resolve_token()
    slugs: list[str] = []
    for kind in ("users", "orgs"):
        for acct in gconf.get(kind, []) or []:
            slugs += github_api.list_repos(acct, kind, token,
                                           gconf.get("include_forks", False),
                                           gconf.get("include_archived", False))
    # With a GitHub App and no explicit accounts, scan everything the install can see.
    if source == "github-app" and not slugs:
        slugs += github_api.list_installation_repos(token, gconf.get("include_archived", False))
    return sorted(set(slugs)), token, source


def scan(config_path: str | None = None, local_only: bool = False,
         fail_on_findings: bool = False, reports_dir: str | Path | None = None,
         paths: list[str] | None = None) -> int:
    cfg = _read_config(config_path)
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])

    # --- resolve WHAT to scan (targets are orthogonal to auth: local needs no token) --
    cfg_targets = cfg.get("targets", {}) or {}
    cfg_local = cfg_targets.get("local", []) or []
    gh = cfg_targets.get("github", {}) or {}
    remote_configured = bool(gh.get("users") or gh.get("orgs"))

    cwd_default = False
    if paths:                                  # explicit ad-hoc paths…
        local_patterns = list(paths)
        local_only = True                      # …are a local-only scan (no token needed)
    elif cfg_local:                            # configured local globs
        local_patterns = list(cfg_local)
    elif local_only or not remote_configured:  # bare run → scan the current repo
        local_patterns = [str(_enclosing_repo_root())]
        cwd_default = True
    else:                                       # remote-only config: no CWD fallback
        local_patterns = []

    if cwd_default:
        print(f"No targets configured; scanning current repository: {local_patterns[0]}")

    results: list[ScanResult] = []
    for repo in discover_local_repos(local_patterns, opts):
        display = str(repo).replace(os.path.expanduser("~"), "~")
        with LocalRepoTarget(repo, display, opts) as t:
            results.append(scan_target(t, sigs, allowlist))

    if not local_only:
        slugs, token, source = _resolve_remote(cfg, opts)
        if slugs and source:
            print(f"GitHub credential: using {source}.")
        elif slugs:
            print("No GitHub credential found; scanning public remotes anonymously. "
                  "For private repos, run `gh auth login` or set GH_SECURITY_TOKEN.")
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
            "suspicious": sum(1 for r in results if r.suspicious),
            "findings": sum(len(r.findings) for r in results),
            "critical": sum(1 for r in results for f in r.findings if f.severity.label() == "critical"),
            "high": sum(1 for r in results for f in r.findings if f.severity.label() == "high"),
        },
        "any_infected": any(r.infected for r in results),
        "any_suspicious": any(r.suspicious for r in results),
        "results": [r.to_dict() for r in results],
    }
    rdir = resolve_reports_dir(reports_dir, settings_value=settings.get("reports_dir"),
                               default=REPORTS_DIR, label="security reports")
    write_json(rdir / "latest.json", payload)
    (rdir / "latest.md").write_text(_render_markdown(payload), encoding="utf-8")

    s = payload["summary"]
    print(f"Scanned {s['targets']} target(s): {s['infected']} infected, "
          f"{s['suspicious']} suspicious, "
          f"{s['findings']} findings ({s['critical']} critical, {s['high']} high)")
    for r in results:
        tag = ("INFECTED" if r.infected else "SUSPECT" if r.suspicious
               else "ERROR" if r.error else "clean")
        print(f"  [{tag:8}] {r.target}  ({len(r.findings)} findings)")
    if s["suspicious"]:
        print("  ↳ 'suspicious' = heuristic match(es) to review; not asserted as infected. "
              "See reports/security/latest.md.")

    # Gate fails on INFECTED only (confirmed findings). Whether SUSPICIOUS should also
    # fail the gate is a CI policy decision tracked in #1058, intentionally not changed here.
    return 1 if (fail_on_findings and payload["any_infected"]) else 0
