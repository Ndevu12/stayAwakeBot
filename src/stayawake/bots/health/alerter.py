#!/usr/bin/env python3
"""Decide and dispatch availability alerts (Slack + GitHub issues).

Single responsibility: alerting policy + dispatch. Network I/O is delegated to
the slack and github_api adapters.

Issue model: ONE self-updating issue per monitored project. The GitHub issue is
the source of truth (found by a stable hidden marker), not a flag in history — so
a lost/rebuilt history can never produce duplicate issues. The body is refreshed
silently (edits don't notify); a comment is posted only on a state transition
(first DOWN, then recovery), and the issue is closed on recovery.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from stayawake.core.adapters.slack import send_slack
from stayawake.core.adapters import github_api
from stayawake.core.config import load_yaml
from stayawake.core.io import read_json
from stayawake.core.timeutil import utc_stamp

LABEL = "stayawakebot-sentinel"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-") or "project"


def _marker(slug: str) -> str:
    return f"<!-- stayawakebot-sentinel:{slug} -->"


def _title(name: str) -> str:
    return f"\U0001F534 {name} — DOWN"   # 🔴


def _consecutive_failures(history: list, name: str) -> int:
    count = 0
    for run in reversed(history):
        found = next((u for u in run.get("urls", []) if u.get("name") == name), None)
        if found is None or found.get("healthy"):
            break
        count += 1
    return count


def _consecutive_healthy(history: list, name: str) -> int:
    count = 0
    for run in reversed(history):
        found = next((u for u in run.get("urls", []) if u.get("name") == name), None)
        if found is None or not found.get("healthy"):
            break
        count += 1
    return count


def _transitions(history: list, name: str) -> list[dict]:
    """State changes (healthy<->unhealthy) for one project, oldest first."""
    out: list[dict] = []
    prev: bool | None = None
    for run in history:
        u = next((x for x in run.get("urls", []) if x.get("name") == name), None)
        if u is None:
            continue
        h = bool(u.get("healthy"))
        if prev is None or h != prev:
            out.append({"at": u.get("checked_at") or run.get("generated_at"),
                        "healthy": h, "reason": u.get("reason") or u.get("error")})
            prev = h
    return out


def _fmt_ts(iso: str | None) -> str:
    if not iso:
        return "unknown"
    try:
        from datetime import datetime
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(iso)


def _humanize(start_iso: str | None, end_iso: str | None) -> str:
    try:
        from datetime import datetime
        start = datetime.fromisoformat(start_iso)
        end = datetime.fromisoformat(end_iso) if end_iso else None
        if end is None:
            from stayawake.core.timeutil import now_iso
            end = datetime.fromisoformat(now_iso())
        secs = max(0, int((end - start).total_seconds()))
        h, rem = divmod(secs, 3600)
        m, _ = divmod(rem, 60)
        return f"{h}h {m:02d}m" if h else f"{m}m"
    except Exception:
        return "—"


def _outage_start(transitions: list[dict]) -> str | None:
    """Timestamp of the most recent DOWN transition (start of the current outage)."""
    for t in reversed(transitions):
        if not t["healthy"]:
            return t["at"]
    return None


def _incident_log(transitions: list[dict], limit: int = 10) -> str:
    rows = []
    # newest first; pair each recovery with the preceding outage to show downtime
    for i in range(len(transitions) - 1, -1, -1):
        t = transitions[i]
        when = _fmt_ts(t["at"])
        if t["healthy"]:
            down_at = transitions[i - 1]["at"] if i > 0 else None
            dur = f" (down {_humanize(down_at, t['at'])})" if down_at else ""
            rows.append(f"| {when} | \U0001F7E2 Recovered{dur} |")
        else:
            reason = t.get("reason") or "unhealthy"
            rows.append(f"| {when} | \U0001F534 DOWN — {reason} |")
    extra = len(rows) - limit
    rows = rows[:limit]
    table = ("| When (UTC) | Event |\n|---|---|\n" + "\n".join(rows)) if rows else "_no recorded transitions_"
    if extra > 0:
        table += f"\n\n*+{extra} earlier transition(s) — see `reports/history.json`*"
    return table


def _render_body(name: str, url: str, u: dict, history: list, slug: str) -> str:
    reason = u.get("reason") or u.get("error") or "unhealthy"
    transitions = _transitions(history, name)
    since = _outage_start(transitions)
    code = u.get("status_code") if u.get("status_code") is not None else "—"
    rms = f"{u.get('response_ms')} ms" if u.get("response_ms") is not None else "—"
    dns = f" · DNS {u.get('dns_ms')} ms" if u.get("dns_ms") is not None else ""
    consec = _consecutive_failures(history, name)
    return "\n".join([
        _marker(slug),
        f"### \U0001F534 DOWN — {reason}",
        f"**{url}**",
        "",
        "| | |",
        "|---|---|",
        f"| Status | \U0001F534 Unhealthy since **{_fmt_ts(since)}** ({_humanize(since, None)}) |",
        f"| Failing check | {reason} |",
        f"| HTTP | {code} · {rms}{dns} |",
        f"| Consecutive failures | {consec} |",
        f"| Last checked | {_fmt_ts(u.get('checked_at'))} |",
        "",
        "<details><summary>Incident log (last 10 transitions)</summary>",
        "",
        _incident_log(transitions),
        "</details>",
        "",
        f"<sub>Auto-updated by StayAwakeBot Sentinel · last update {utc_stamp()} · "
        f"body edits are silent; comments only on state changes.</sub>",
    ])


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
    owner = repo_name = None
    if repo and "/" in repo:
        owner, repo_name = repo.split("/", 1)

    try:
        settings = load_yaml("config/urls.yml").get("settings", {})
    except Exception:
        settings = {}
    fail_threshold = int(settings.get("consecutive_failures_before_alert", 1))
    # Recovery debounce: N consecutive healthy checks before we declare recovery.
    recovery_threshold = int(settings.get("consecutive_healthy_before_recovery", fail_threshold))
    alert_on_failure = settings.get("alert_on_failure", True)
    alert_on_recovery = settings.get("alert_on_recovery", True)

    curr_run = history[-1]

    for u in curr_run.get("urls", []):
        name, url, healthy = u.get("name"), u.get("url"), u.get("healthy")
        slug = _slug(name)
        marker = _marker(slug)
        reason = u.get("reason") or u.get("error") or "unhealthy"

        open_issue = None
        if owner and repo_name and token:
            open_issue = github_api.find_issue_by_marker(
                owner, repo_name, marker, token, labels=LABEL)

        if not healthy:
            if not alert_on_failure:
                continue
            consec = _consecutive_failures(history, name)
            if consec < fail_threshold:
                continue
            body = _render_body(name, url, u, history, slug)

            if owner and repo_name and token:
                if open_issue is None:
                    github_api.create_issue(owner, repo_name, _title(name), body,
                                            token, labels=[LABEL])
                else:
                    # Refresh the existing issue in place — no notification.
                    github_api.update_issue(owner, repo_name, open_issue["number"],
                                            token, title=_title(name), body=body)

            # Slack only on the DOWN transition (the run it first crosses the threshold).
            if slack_webhook and consec == fail_threshold:
                send_slack(slack_webhook, {"text": "StayAwakeBot Sentinel Alert", "attachments": [{
                    "color": "#ff0000", "title": f"DOWN: {name}", "title_link": url,
                    "text": f"{reason}\nStatus: {u.get('status_code')} | "
                            f"Response: {u.get('response_ms')}ms",
                    "footer": f"StayAwakeBot Sentinel | {utc_stamp()}",
                    "fields": [{"title": "Consecutive failures", "value": str(consec),
                                "short": True}]}]})

        else:  # healthy
            if not alert_on_recovery:
                continue
            consec_ok = _consecutive_healthy(history, name)
            if consec_ok < recovery_threshold:
                continue   # within the debounce window; not declared recovered yet

            if owner and repo_name and token and open_issue is not None:
                since = _outage_start(_transitions(history, name))
                downtime = _humanize(since, u.get("checked_at"))
                github_api.add_issue_comment(
                    owner, repo_name, open_issue["number"],
                    f"\U0001F7E2 **Recovered** at {_fmt_ts(u.get('checked_at'))} "
                    f"after {downtime}. Closing — the sentinel will reopen a fresh issue "
                    f"if it goes down again.", token)
                github_api.update_issue(owner, repo_name, open_issue["number"],
                                        token, state="closed")

            if slack_webhook and consec_ok == recovery_threshold:
                send_slack(slack_webhook, {"text": "StayAwakeBot Sentinel Alert", "attachments": [{
                    "color": "#36a64f", "title": f"RECOVERY: {name}", "title_link": url,
                    "text": f"Recovered at {utc_stamp()}",
                    "footer": f"StayAwakeBot Sentinel | {utc_stamp()}"}]})

    print("Alerts processed (if any).")
