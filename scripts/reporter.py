#!/usr/bin/env python3
"""Reporter for StayAwakeBot: builds markdown, status.json, and history.json from reports/latest.json
"""
from __future__ import annotations
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import urllib.parse

from helpers.reporter_helpers import (
    parse_args,
    utc_iso_now,
    read_json,
    update_readme_badge,
    compute_uptime,
)


def main() -> None:
    args = parse_args()
    latest_path = Path(args.latest)
    reports_dir = Path("reports")
    history_path = reports_dir / "history.json"
    status_path = reports_dir / "status.json"
    if not latest_path.exists():
        print("latest.json not found; run checker first")
        return
    latest = json.loads(latest_path.read_text())
    generated_at = latest.get("generated_at")
    results = latest.get("results", [])

    history = read_json(history_path) or []

    run_entry = {"generated_at": generated_at, "urls": []}
    total_resp = 0
    resp_count = 0
    healthy_count = 0
    for r in results:
        run_entry["urls"].append({
            "name": r.get("name"),
            "url": r.get("url"),
            "dns_ms": r.get("dns_ms"),
            "healthy": bool(r.get("healthy")),
            "status_code": r.get("status_code"),
            "response_ms": r.get("response_ms"),
            "error": r.get("error"),
            "checked_at": r.get("checked_at"),
            "tags": r.get("tags", []),
            "alerted": False,
        })
        if r.get("response_ms") is not None:
            total_resp += int(r.get("response_ms"))
            resp_count += 1
        if r.get("healthy"):
            healthy_count += 1
    # Avoid duplicating runs if checker already persisted a minimal entry
    if not any(h.get("generated_at") == generated_at for h in history):
        history.append(run_entry)
        history_path.write_text(json.dumps(history, indent=2))
    else:
        # If an entry with this generated_at exists, merge/ensure fields are present
        for h in history:
            if h.get("generated_at") == generated_at:
                # ensure urls list contains same structure; prefer reporter's richer fields
                h_urls = {u.get("name"): u for u in h.get("urls", [])}
                for new_u in run_entry.get("urls", []):
                    name = new_u.get("name")
                    if name in h_urls:
                        # merge keys from reporter run into existing entry
                        h_urls[name].update(new_u)
                    else:
                        h.get("urls", []).append(new_u)
        history_path.write_text(json.dumps(history, indent=2))

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    status = {
        "generated_at": generated_at,
        "summary": {
            "total": len(results),
            "healthy": healthy_count,
            "unhealthy": len(results) - healthy_count,
            "avg_response_ms": int(total_resp / resp_count) if resp_count else None,
        },
        "urls": [],
    }
    for r in results:
        up_pct = compute_uptime(r.get("name"), history, cutoff)
        status["urls"].append({
            "name": r.get("name"),
            "url": r.get("url"),
            "dns_ms": r.get("dns_ms"),
            "healthy": bool(r.get("healthy")),
            "status_code": r.get("status_code"),
            "response_ms": r.get("response_ms"),
            "uptime_30d_pct": up_pct,
            "last_checked": r.get("checked_at"),
        })

    status_path.write_text(json.dumps(status, indent=2))

    dt = datetime.fromisoformat(generated_at)
    out_dir = reports_dir / dt.strftime("%Y-%m-%d")
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / dt.strftime("%H-%M-UTC.md")

    avg_resp = status["summary"]["avg_response_ms"] or "—"
    md_lines = []
    md_lines.append(f"# Health report — {dt.strftime('%Y-%m-%d %H:%M UTC')}")
    md_lines.append("")
    md_lines.append(f"**Run summary:** {len(results)} checked · {healthy_count} healthy · {len(results)-healthy_count} down · avg response {avg_resp}ms")
    md_lines.append("")
    md_lines.append("## Results")
    md_lines.append("")
    md_lines.append("| Name | Status | Code | Response | DNS | SSL | Uptime (30d) |")
    md_lines.append("|------|--------|------|----------|-----|-----|--------------|")
    for r in results:
        name = r.get("name")
        status_icon = "✅ OK" if r.get("healthy") else "❌ DOWN"
        code = r.get("status_code") or "—"
        response = f"{r.get('response_ms')}ms" if r.get("response_ms") else (r.get("error") or "—")
        dns_field = f"{r.get('dns_ms')}ms" if r.get('dns_ms') is not None else "—"
        ssl_field = "—"
        if r.get("ssl") and isinstance(r.get("ssl"), dict) and r.get("ssl").get("expires_in_days") is not None:
            ssl_field = f"{r['ssl']['expires_in_days']}d"
        uptime = next((u["uptime_30d_pct"] for u in status["urls"] if u["name"] == name), "—")
        md_lines.append(f"| {name} | {status_icon} | {code} | {response} | {dns_field} | {ssl_field} | {uptime}% |")

    md_lines.append("")
    md_lines.append("## Details")
    md_lines.append("")
    for r in results:
        md_lines.append(f"### {r.get('name')}")
        md_lines.append(f"- URL: `{r.get('url')}`")
        if r.get('dns_ms') is not None:
            md_lines.append(f"- DNS resolution: {r.get('dns_ms')}ms")
        md_lines.append(f"- Checked at: {r.get('checked_at')}")
        md_lines.append(f"- Redirects: {r.get('redirect_count')}")
        tags = ", ".join(r.get('tags') or [])
        md_lines.append(f"- Tags: {tags}")
        if r.get("error"):
            md_lines.append(f"- Error: {r.get('error')}")
        md_lines.append("")

    md_path.write_text("\n".join(md_lines))

    readme = Path("README.md")
    update_readme_badge(readme, healthy_count, len(results))

    print(f"Wrote report: {md_path}")
    print(f"Wrote status: {status_path}")
    print(f"Updated history: {history_path}")


if __name__ == "__main__":
    main()
