#!/usr/bin/env python3
"""Slack webhook adapter (single responsibility: post to Slack)."""
from __future__ import annotations

import json
import urllib.request


def send_slack(webhook: str, payload: dict) -> str | None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(webhook, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode()
    except Exception as e:  # noqa: BLE001
        print(f"Slack send failed: {e}")
        return None
