#!/usr/bin/env python3
"""Availability alerting via ONE self-updating 'status' issue — the sentinel's whole store.

Single responsibility: fold the current checks into per-service debounce state, refresh the one
dashboard issue, and Slack on transitions. The issue IS the store: its hidden state block (managed
by `core.issue_state`) holds the debounce counters + recent incidents, so there is NO report file
and NOTHING is committed. The body edit is silent (no notification); Slack + the 🔴/🟢 title are the
alert channel. Best-effort — a missing token / unreachable GitHub never affects the checker's exit.
"""
from __future__ import annotations

from stayawake.core import env
from stayawake.core import issue_state
from stayawake.core.adapters.slack import send_slack
from stayawake.core.timeutil import now_iso, utc_stamp

LABEL = "availability-status"
MARKER = "<!-- stayawakebot-sentinel:status -->"
_MAX_INCIDENTS = 15


def _fmt_ts(iso: str | None) -> str:
    if not iso:
        return "unknown"
    try:
        from datetime import datetime
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return str(iso)


def _humanize(start_iso: str | None, end_iso: str | None) -> str:
    try:
        from datetime import datetime
        start = datetime.fromisoformat(start_iso)
        end = datetime.fromisoformat(end_iso) if end_iso else datetime.fromisoformat(now_iso())
        secs = max(0, int((end - start).total_seconds()))
        h, rem = divmod(secs, 3600)
        m, _ = divmod(rem, 60)
        return f"{h}h {m:02d}m" if h else f"{m}m"
    except (ValueError, TypeError):
        return "—"


def _fold(prev: dict, results: list[dict], fail_threshold: int, recovery_threshold: int
          ) -> tuple[dict, list[dict]]:
    """Fold the current results into prior per-service state; surface DOWN/RECOVERY events.

    Debounce lives here (in the issue's state block): a service must fail `fail_threshold`
    consecutive checks to raise DOWN, and pass `recovery_threshold` consecutive checks (while
    alerted) to raise RECOVERY — so a transient blip never fires."""
    services = prev.get("services") if isinstance(prev.get("services"), dict) else {}
    out: dict = {}
    events: list[dict] = []
    now = now_iso()
    for r in results:
        name = r.get("name")
        if not name:
            continue
        healthy = bool(r.get("healthy"))
        p = services.get(name) if isinstance(services.get(name), dict) else {}
        fails = 0 if healthy else int(p.get("consec_fail", 0) or 0) + 1
        heals = int(p.get("consec_heal", 0) or 0) + 1 if healthy else 0
        alerted = bool(p.get("alerted", False))
        down_since = p.get("down_since")
        incidents = p.get("incidents") if isinstance(p.get("incidents"), list) else []
        reason = r.get("reason") or r.get("error") or "unhealthy"

        if not alerted and not healthy and fails >= fail_threshold:
            alerted, down_since = True, now
            incidents = ([{"at": now, "up": False, "reason": reason}] + incidents)[:_MAX_INCIDENTS]
            events.append({"name": name, "kind": "down", "reason": reason, "url": r.get("url")})
        elif alerted and healthy and heals >= recovery_threshold:
            incidents = ([{"at": now, "up": True, "since": down_since}] + incidents)[:_MAX_INCIDENTS]
            events.append({"name": name, "kind": "recovery", "url": r.get("url"),
                           "downtime": _humanize(down_since, now)})
            alerted, down_since = False, None

        out[name] = {"consec_fail": fails, "consec_heal": heals, "alerted": alerted,
                     "down_since": down_since, "incidents": incidents}
    return {"services": out, "updated_at": now}, events


def _render(state: dict, results: list[dict]) -> tuple[str, str]:
    """(title, body) for the dashboard issue: 🔴/🟢 title (the only notifying signal on an otherwise
    silent edit), a status table, per-service incident logs, and the hidden state block."""
    services = state.get("services", {})
    up = sum(1 for r in results if r.get("healthy"))
    total = len(results)
    any_alerted = any(s.get("alerted") for s in services.values())
    title = f"{'🔴' if any_alerted else '🟢'} Availability status — {up}/{total} up"

    rows = ["| Service | State | HTTP | Response | Failing check |", "|---|---|---|---|---|"]
    for r in results:
        healthy = bool(r.get("healthy"))
        code = r.get("status_code") if r.get("status_code") is not None else "—"
        rms = f"{r.get('response_ms')} ms" if r.get("response_ms") is not None else "—"
        why = "—" if healthy else (r.get("reason") or r.get("error") or "unhealthy")
        rows.append(f"| {r.get('name')} | {'🟢 Up' if healthy else '🔴 Down'} | {code} | {rms} | {why} |")

    lines = [MARKER, "## 📊 Availability status", "",
             f"**{up}/{total} up** · {total - up} down · updated {utc_stamp()}", "", *rows, ""]
    logged = [(n, s) for n, s in services.items() if s.get("incidents")]
    if logged:
        lines += ["<details><summary>Recent incidents</summary>", ""]
        for name, s in logged:
            lines.append(f"**{name}**")
            for ev in s["incidents"][:_MAX_INCIDENTS]:
                if ev.get("up"):
                    lines.append(f"- {_fmt_ts(ev.get('at'))} — 🟢 Recovered "
                                 f"(down {_humanize(ev.get('since'), ev.get('at'))})")
                else:
                    lines.append(f"- {_fmt_ts(ev.get('at'))} — 🔴 DOWN — {ev.get('reason') or 'unhealthy'}")
            lines.append("")
        lines.append("</details>")
    lines += ["", "<sub>Auto-updated by StayAwakeBot Sentinel — one silent, self-updating dashboard "
              "(body edits don't notify; outages ping Slack and flip the title 🔴).</sub>",
              "", issue_state.state_comment(state)]
    return title, "\n".join(lines)


def publish(results: list[dict], settings: dict | None = None) -> None:
    """Refresh the one dashboard issue from `results` and Slack any DOWN/RECOVERY transition."""
    settings = settings or {}
    token = env.github_token()
    slug = env.github_slug()
    if not (token and slug):
        print("alerter: GITHUB_TOKEN/GITHUB_REPOSITORY unset — skipping issue update", flush=True)
        return
    owner, repo_name = slug
    fail_threshold = int(settings.get("consecutive_failures_before_alert", 2) or 1)
    recovery_threshold = int(settings.get("consecutive_healthy_before_recovery", fail_threshold) or 1)

    _, prev = issue_state.load(owner, repo_name, MARKER, token, label=LABEL)
    state, events = _fold(prev, results, fail_threshold, recovery_threshold)
    title, body = _render(state, results)
    issue_state.save(owner, repo_name, MARKER, token, title=title, body=body, label=LABEL)

    webhook = env.slack_webhook()
    if webhook:
        for ev in events:
            if ev["kind"] == "down" and settings.get("alert_on_failure", True):
                send_slack(webhook, {"text": f"🔴 {ev['name']} is DOWN — {ev['reason']} "
                                             f"({ev.get('url') or ''})"})
            elif ev["kind"] == "recovery" and settings.get("alert_on_recovery", True):
                send_slack(webhook, {"text": f"🟢 {ev['name']} RECOVERED after {ev.get('downtime')} "
                                             f"({ev.get('url') or ''})"})
    print("Alerts processed (if any).")
