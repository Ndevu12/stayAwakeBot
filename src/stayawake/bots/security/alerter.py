#!/usr/bin/env python3
"""Security alerting: open a GitHub issue per infected repo, close on recovery,
and post a Slack summary.

Single responsibility: alerting policy + dispatch. Idempotent — it keys off the
existence of an open, labelled issue per target, so re-runs don't spam.
"""
from __future__ import annotations

import os
import urllib.parse
from pathlib import Path

from stayawake.core.adapters.slack import send_slack
from stayawake.core.adapters import github_api
from stayawake.core.io import read_json
from stayawake.core.timeutil import utc_stamp

LABEL = "stayawakebot-security"


def _title(target: str) -> str:
    return f"[SECURITY] worm indicators in {target}"


def _open_issues(owner: str, name: str, token: str) -> list[dict]:
    q = urllib.parse.quote_plus(f"repo:{owner}/{name} label:{LABEL} state:open")
    res = github_api.request(f"/search/issues?q={q}", token=token)
    return res.get("items", []) if res else []


def _issue_body(result: dict) -> str:
    lines = [f"StayAwakeBot Security Sentinel detected worm indicators in "
             f"`{result['target']}` ({result['source']}).", "",
             f"**Detected at:** {utc_stamp()}",
             f"**Findings:** {result['summary']['total']} "
             f"(max severity: {result['summary']['max_severity']})", "", "| Severity | Signature | Path |",
             "|----------|-----------|------|"]
    for f in result.get("findings", [])[:25]:
        loc = f["path"] + (f":{f['line']}" if f.get("line") else "")
        lines.append(f"| {f['severity']} | `{f['signature_id']}` | {loc} |")
    lines += ["", "Auto-opened by StayAwakeBot Security Sentinel. Will auto-close when the "
              "target scans clean. Clean with `~/sec-clean-worm.sh` or the remediator (Phase 3)."]
    return "\n".join(lines)


def run(latest_path: str | Path = "reports/security/latest.json") -> None:
    latest = read_json(latest_path)
    if latest is None:
        print("security latest.json not found; run the scanner first")
        return

    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    slack = os.environ.get("SLACK_WEBHOOK_URL")

    results = latest.get("results", [])
    infected = [r for r in results if r.get("infected")]
    clean = [r for r in results if not r.get("infected") and not r.get("error")]

    if infected and slack:
        send_slack(slack, {"text": "StayAwakeBot Security Sentinel", "attachments": [{
            "color": "#ff0000",
            "title": f"⚠️ Worm indicators in {len(infected)} repo(s)",
            "text": "\n".join(f"• {r['target']} — {r['summary']['total']} findings "
                              f"({r['summary']['max_severity']})" for r in infected[:20]),
            "footer": f"StayAwakeBot Security Sentinel | {utc_stamp()}"}]})

    if not (token and repo):
        print(f"Security alerts: {len(infected)} infected (no token/repo — skipped GitHub issues).")
        return

    owner, name = repo.split("/")
    open_by_title = {it.get("title"): it for it in _open_issues(owner, name, token)}

    for r in infected:
        if _title(r["target"]) not in open_by_title:
            github_api.request(f"/repos/{owner}/{name}/issues", method="POST", token=token,
                               data={"title": _title(r["target"]), "body": _issue_body(r),
                                     "labels": [LABEL]})
    for r in clean:
        it = open_by_title.get(_title(r["target"]))
        if it and it.get("number") is not None:
            github_api.request(f"/repos/{owner}/{name}/issues/{it['number']}",
                               method="PATCH", token=token, data={"state": "closed"})
    print(f"Security alerts processed: {len(infected)} infected, {len(clean)} clean.")
