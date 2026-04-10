#!/usr/bin/env python3
"""Alerter for StayAwakeBot Sentinel — sends Slack and GitHub alerts based on reports/latest.json and history.json
"""
from __future__ import annotations
import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import urllib.parse

from helpers.alerter_helpers import (
    parse_args, utc_now_str, 
    send_slack, github_api, title_for_issue
)


def main() -> None:
    args = parse_args()
    latest_path = Path(args.latest)
    history_path = Path(args.history)
    if not latest_path.exists() or not history_path.exists():
        print("latest.json or history.json missing; ensure checker and reporter ran")
        return
    latest = json.loads(latest_path.read_text())
    history = json.loads(history_path.read_text())
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")

    prev_run = history[-2] if len(history) >= 2 else None
    curr_run = history[-1]
    # try to read config for thresholds
    try:
        cfg = Path("config/urls.yml")
        import yaml
        settings = yaml.safe_load(cfg.read_text()).get("settings", {})
    except Exception:
        settings = {"consecutive_failures_before_alert": 1, "alert_on_recovery": True, "alert_on_failure": True}

    threshold = int(settings.get("consecutive_failures_before_alert", 1))

    def consecutive_failures(name: str) -> int:
        count = 0
        for run in reversed(history):
            found = next((u for u in run.get("urls", []) if u.get("name") == name), None)
            if found is None:
                break
            if found.get("healthy"):
                break
            count += 1
        return count

    for u in curr_run.get("urls", []):
        name = u.get("name")
        url = u.get("url")
        healthy = u.get("healthy")
        prev = None
        if prev_run:
            prev = next((x for x in prev_run.get("urls", []) if x.get("name") == name), None)
        if healthy and prev and not prev.get("healthy") and settings.get("alert_on_recovery", True):
            if slack_webhook:
                payload = {
                    "text": "StayAwakeBot Sentinel Alert",
                    "attachments": [
                        {
                            "color": "#36a64f",
                            "title": f"RECOVERY: {name}",
                            "title_link": url,
                            "text": f"Recovered at {utc_now_str()}",
                            "footer": f"StayAwakeBot Sentinel | {utc_now_str()}",
                        }
                    ],
                }
                send_slack(slack_webhook, payload)
            if token and repo:
                owner, repo_name = repo.split("/")
                q = urllib.parse.quote_plus(f"repo:{owner}/{repo_name} label:stayawakebot-sentinel state:open {name}")
                search = f"/search/issues?q={q}"
                res = github_api(search, token=token)
                if res and res.get("items"):
                    for it in res.get("items"):
                        issue_url = it.get("url")
                        _ = github_api(issue_url.replace("https://api.github.com", ""), method="PATCH", token=token, data={"state": "closed"})
        if not healthy:
            already_alerted = False
            if prev and prev.get("alerted"):
                already_alerted = True
            consec = consecutive_failures(name)
            if consec >= threshold and not already_alerted and settings.get("alert_on_failure", True):
                reason = u.get("error") or "unhealthy"
                text = f"DOWN: {name} — {url}\nStatus: {u.get('status_code')} | Response: {u.get('response_ms')}ms | {reason}"
                if slack_webhook:
                    payload = {
                        "text": "StayAwakeBot Sentinel Alert",
                        "attachments": [
                            {
                                "color": "#ff0000",
                                "title": f"DOWN: {name}",
                                "title_link": url,
                                "text": text,
                                "footer": f"StayAwakeBot Sentinel | {utc_now_str()}",
                                "fields": [
                                    {"title": "Consecutive failures", "value": str(consec), "short": True},
                                ],
                            }
                        ],
                    }
                    send_slack(slack_webhook, payload)
                if token and repo:
                    owner, repo_name = repo.split("/")
                    issue = {
                        "title": title_for_issue("DOWN", name, url),
                        "body": f"## StayAwakeBot Sentinel detected an availability issue\n\n**URL:** {url}\n**Detected at:** {utc_now_str()}\n**Status code:** {u.get('status_code')}\n**Response time:** {u.get('response_ms')}ms\n**Reason:** {reason}\n**Consecutive failures:** {consec}\n\nAuto-opened by StayAwakeBot Sentinel. Will be auto-closed on recovery.",
                        "labels": ["stayawakebot-sentinel"],
                    }
                    _ = github_api(f"/repos/{owner}/{repo_name}/issues", method="POST", token=token, data=issue)
                u["alerted"] = True

    Path(args.history).write_text(json.dumps(history, indent=2))
    print("Alerts processed (if any).")


if __name__ == "__main__":
    main()
