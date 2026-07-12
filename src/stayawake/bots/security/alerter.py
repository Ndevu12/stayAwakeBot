#!/usr/bin/env python3
"""Security alerting: open a GitHub issue per infected repo, close on recovery,
and post a Slack summary.

Single responsibility: alerting policy + dispatch. Idempotent — it keys off the
existence of an open, labelled issue per target, so re-runs don't spam. Both entry
points take an in-memory scan payload (the `--alert` sinks pass it straight from the
scan, no intermediate report file on disk).
"""
from __future__ import annotations

import urllib.parse

from stayawake.core import env
from stayawake.core.adapters.slack import send_slack
from stayawake.core.adapters import github_api
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


def post_slack_summary(payload: dict) -> None:
    """Post the infected / suspicious Slack summaries for a scan payload (no-op without
    SLACK_WEBHOOK_URL). Bodies are evidence-free."""
    slack = env.slack_webhook()
    if not slack:
        return
    results = payload.get("results", [])
    infected = [r for r in results if r.get("infected")]
    suspicious = [r for r in results if r.get("suspicious")]

    if infected:
        send_slack(slack, {"text": "StayAwakeBot Security Sentinel", "attachments": [{
            "color": "#ff0000",
            "title": f"⚠️ Worm indicators in {len(infected)} repo(s)",
            "text": "\n".join(f"• {r['target']} — {r['summary']['total']} findings "
                              f"({r['summary']['max_severity']})" for r in infected[:20]),
            "footer": f"StayAwakeBot Security Sentinel | {utc_stamp()}"}]})
    if suspicious:
        # Softer, distinct alert — informs without crying "malware" on heuristic-only hits.
        send_slack(slack, {"text": "StayAwakeBot Security Sentinel", "attachments": [{
            "color": "#dbab09",
            "title": f"🟡 {len(suspicious)} repo(s) with items to review (not confirmed)",
            "text": "\n".join(f"• {r['target']} — {r['summary']['total']} heuristic finding(s)"
                              for r in suspicious[:20]),
            "footer": f"StayAwakeBot Security Sentinel | {utc_stamp()}"}]})


def sync_github_issues(payload: dict) -> None:
    """Open one labelled issue per infected repo and close it on recovery (idempotent,
    keyed on the open issue's title). No-op with a note when no GITHUB_TOKEN/REPOSITORY."""
    token = env.github_token()
    slug = env.github_slug()

    results = payload.get("results", [])
    infected = [r for r in results if r.get("infected")]
    suspicious = [r for r in results if r.get("suspicious")]
    # A suspicious repo is neither infected nor clean: don't auto-close its issue, and
    # don't open one either — only confirmed-infected repos get a GitHub issue.
    clean = [r for r in results if not r.get("infected")
             and not r.get("suspicious") and not r.get("error")]

    if not (token and slug):
        print(f"Security alerts: {len(infected)} infected, {len(suspicious)} suspicious "
              "(no token/repo — skipped GitHub issues).")
        return

    owner, name = slug
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
    print(f"Security alerts processed: {len(infected)} infected, "
          f"{len(suspicious)} suspicious, {len(clean)} clean.")
