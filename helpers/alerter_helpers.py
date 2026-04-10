#!/usr/bin/env python3
import argparse
import json
import urllib.request
from datetime import datetime, timezone
from typing import Optional


def parse_args():
    p = argparse.ArgumentParser(description="Send alerts based on latest and history")
    p.add_argument("--latest", default="reports/latest.json")
    p.add_argument("--history", default="reports/history.json")
    return p.parse_args()


def utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def send_slack(webhook: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode()
    except Exception as e:
        print(f"Slack send failed: {e}")
        return None


def github_api(req_path: str, method: str = "GET", token: Optional[str] = None, data: Optional[dict] = None):
    url = f"https://api.github.com{req_path}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as he:
        try:
            payload = he.read().decode()
        except Exception:
            payload = str(he)
        print(f"GitHub API error: {he.code} {payload}")
        return None
    except Exception as e:
        print(f"GitHub API request failed: {e}")
        return None


def title_for_issue(prefix: str, name: str, url: str) -> str:
    return f"[{prefix}] {name} — {url}"
