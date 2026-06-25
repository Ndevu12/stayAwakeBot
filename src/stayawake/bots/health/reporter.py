#!/usr/bin/env python3
"""Build status.json, history.json, and the dated markdown report.

Single responsibility: transform `latest.json` into human/machine reports.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path

from stayawake.core.io import read_json, write_json


def compute_uptime(url_name: str, history: list, cutoff: datetime) -> float:
    seen = [h for h in history if datetime.fromisoformat(h["generated_at"]) >= cutoff]
    if not seen:
        return 100.0
    checks = healthy = 0
    for run in seen:
        for u in run.get("urls", []):
            if u.get("name") == url_name:
                checks += 1
                healthy += 1 if u.get("healthy") else 0
    return round((healthy / checks) * 100.0, 1) if checks else 100.0


def _upsert_history(history: list, run_entry: dict, generated_at: str) -> None:
    if not any(h.get("generated_at") == generated_at for h in history):
        history.append(run_entry)
        return
    for h in history:
        if h.get("generated_at") == generated_at:
            existing = {u.get("name"): u for u in h.get("urls", [])}
            for new_u in run_entry.get("urls", []):
                if new_u.get("name") in existing:
                    existing[new_u["name"]].update(new_u)
                else:
                    h.setdefault("urls", []).append(new_u)


def _build_markdown(dt: datetime, results: list, healthy: int, avg_resp, status: dict) -> str:
    lines = [f"# Health report — {dt.strftime('%Y-%m-%d %H:%M UTC')}", "",
             f"**Run summary:** {len(results)} checked · {healthy} healthy · "
             f"{len(results) - healthy} down · avg response {avg_resp}ms", "",
             "## Results", "",
             "| Name | Status | Code | Response | DNS | SSL | Uptime (30d) |",
             "|------|--------|------|----------|-----|-----|--------------|"]
    uptimes = {u["name"]: u["uptime_30d_pct"] for u in status["urls"]}
    for r in results:
        icon = "✅ OK" if r.get("healthy") else "❌ DOWN"
        code = r.get("status_code") or "—"
        response = f"{r.get('response_ms')}ms" if r.get("response_ms") else (r.get("error") or "—")
        dns = f"{r.get('dns_ms')}ms" if r.get("dns_ms") is not None else "—"
        ssl = f"{r['ssl']['expires_in_days']}d" if isinstance(r.get("ssl"), dict) \
            and r["ssl"].get("expires_in_days") is not None else "—"
        lines.append(f"| {r.get('name')} | {icon} | {code} | {response} | {dns} | {ssl} | "
                     f"{uptimes.get(r.get('name'), '—')}% |")
    lines += ["", "## Details", ""]
    for r in results:
        lines.append(f"### {r.get('name')}")
        lines.append(f"- URL: `{r.get('url')}`")
        if r.get("dns_ms") is not None:
            lines.append(f"- DNS resolution: {r.get('dns_ms')}ms")
        lines.append(f"- Checked at: {r.get('checked_at')}")
        lines.append(f"- Redirects: {r.get('redirect_count')}")
        lines.append(f"- Tags: {', '.join(r.get('tags') or [])}")
        if r.get("error"):
            lines.append(f"- Error: {r.get('error')}")
        lines.append("")
    return "\n".join(lines)


def generate(latest_path: str | Path = "reports/latest.json",
             reports_dir: str | Path = "reports") -> None:
    latest = read_json(latest_path)
    if latest is None:
        print("latest.json not found; run checker first")
        return
    reports_dir = Path(reports_dir)
    results = latest.get("results", [])
    generated_at = latest.get("generated_at")

    history = read_json(reports_dir / "history.json", []) or []
    healthy = sum(1 for r in results if r.get("healthy"))
    resp = [int(r["response_ms"]) for r in results if r.get("response_ms") is not None]
    run_entry = {"generated_at": generated_at, "urls": [{
        "name": r.get("name"), "url": r.get("url"), "dns_ms": r.get("dns_ms"),
        "healthy": bool(r.get("healthy")), "status_code": r.get("status_code"),
        "response_ms": r.get("response_ms"), "error": r.get("error"),
        "reason": r.get("reason"),
        "checked_at": r.get("checked_at"), "tags": r.get("tags", []), "alerted": False,
    } for r in results]}
    _upsert_history(history, run_entry, generated_at)
    write_json(reports_dir / "history.json", history)

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    status = {
        "generated_at": generated_at,
        "summary": {"total": len(results), "healthy": healthy,
                    "unhealthy": len(results) - healthy,
                    "avg_response_ms": int(sum(resp) / len(resp)) if resp else None},
        "urls": [{
            "name": r.get("name"), "url": r.get("url"), "dns_ms": r.get("dns_ms"),
            "healthy": bool(r.get("healthy")), "status_code": r.get("status_code"),
            "response_ms": r.get("response_ms"),
            "uptime_30d_pct": compute_uptime(r.get("name"), history, cutoff),
            "last_checked": r.get("checked_at"),
        } for r in results],
    }
    write_json(reports_dir / "status.json", status)

    dt = datetime.fromisoformat(generated_at)
    out_dir = reports_dir / dt.strftime("%Y-%m-%d")
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / dt.strftime("%H-%M-UTC.md")
    md_path.write_text(_build_markdown(dt, results, healthy,
                                       status["summary"]["avg_response_ms"] or "—", status),
                       encoding="utf-8")

    print(f"Wrote report: {md_path}")
    print(f"Wrote status: {reports_dir / 'status.json'}")
