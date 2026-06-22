#!/usr/bin/env python3
"""Decide and dispatch availability alerts (Slack + GitHub issues).

Single responsibility: alerting policy + dispatch. Network I/O is delegated to
the slack and github_api adapters.
"""
from __future__ import annotations

import os
import urllib.parse
from pathlib import Path

from stayawakebot.adapters.slack import send_slack
from stayawakebot.adapters import github_api
from stayawakebot.common.config import load_yaml
from stayawakebot.common.io import read_json, write_json
from stayawakebot.common.timeutil import utc_stamp


def _title(prefix: str, name: str, url: str) -> str:
    return f"[{prefix}] {name} — {url}"


def _consecutive_failures(history: list, name: str) -> int:
    count = 0
    for run in reversed(history):
        found = next((u for u in run.get("urls", []) if u.get("name") == name), None)
        if found is None or found.get("healthy"):
            break
        count += 1
    return count


def run(latest_path: str | Path = "reports/latest.json",
        history_path: str | Path = "reports/history.json") -> None:
    latest = read_json(latest_path)
    history = read_json(history_path)
    if latest is None or history is None:
        print("latest.json or history.json missing; ensure checker and reporter ran")
        return

    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")

    try:
        settings = load_yaml("config/urls.yml").get("settings", {})
    except Exception:
        settings = {}
    threshold = int(settings.get("consecutive_failures_before_alert", 1))

    prev_run = history[-2] if len(history) >= 2 else None
    curr_run = history[-1]

    for u in curr_run.get("urls", []):
        name, url, healthy = u.get("name"), u.get("url"), u.get("healthy")
        prev = next((x for x in prev_run.get("urls", [])), None) if prev_run else None
        prev = next((x for x in (prev_run or {}).get("urls", []) if x.get("name") == name), None) \
            if prev_run else None

        if healthy and prev and not prev.get("healthy") and settings.get("alert_on_recovery", True):
            if slack_webhook:
                send_slack(slack_webhook, {"text": "StayAwakeBot Sentinel Alert", "attachments": [{
                    "color": "#36a64f", "title": f"RECOVERY: {name}", "title_link": url,
                    "text": f"Recovered at {utc_stamp()}", "footer": f"StayAwakeBot Sentinel | {utc_stamp()}"}]})
            if token and repo:
                owner, repo_name = repo.split("/")
                q = urllib.parse.quote_plus(
                    f"repo:{owner}/{repo_name} label:stayawakebot-sentinel state:open {name}")
                res = github_api.request(f"/search/issues?q={q}", token=token)
                for it in (res or {}).get("items", []):
                    api_path = it.get("url", "").replace("https://api.github.com", "")
                    if api_path:
                        github_api.request(api_path, method="PATCH", token=token, data={"state": "closed"})

        if not healthy:
            if prev and prev.get("alerted"):
                continue
            consec = _consecutive_failures(history, name)
            if consec >= threshold and settings.get("alert_on_failure", True):
                reason = u.get("error") or "unhealthy"
                text = (f"DOWN: {name} — {url}\nStatus: {u.get('status_code')} | "
                        f"Response: {u.get('response_ms')}ms | {reason}")
                if slack_webhook:
                    send_slack(slack_webhook, {"text": "StayAwakeBot Sentinel Alert", "attachments": [{
                        "color": "#ff0000", "title": f"DOWN: {name}", "title_link": url, "text": text,
                        "footer": f"StayAwakeBot Sentinel | {utc_stamp()}",
                        "fields": [{"title": "Consecutive failures", "value": str(consec), "short": True}]}]})
                if token and repo:
                    owner, repo_name = repo.split("/")
                    github_api.request(f"/repos/{owner}/{repo_name}/issues", method="POST", token=token, data={
                        "title": _title("DOWN", name, url),
                        "body": (f"## StayAwakeBot Sentinel detected an availability issue\n\n"
                                 f"**URL:** {url}\n**Detected at:** {utc_stamp()}\n"
                                 f"**Status code:** {u.get('status_code')}\n"
                                 f"**Response time:** {u.get('response_ms')}ms\n**Reason:** {reason}\n"
                                 f"**Consecutive failures:** {consec}\n\n"
                                 f"Auto-opened by StayAwakeBot Sentinel. Will be auto-closed on recovery."),
                        "labels": ["stayawakebot-sentinel"]})
                u["alerted"] = True

    write_json(history_path, history)
    print("Alerts processed (if any).")
