#!/usr/bin/env python3
"""Async URL availability checker for StayAwakeBot Sentinel

Usage: python scripts/checker.py --config config/urls.yml
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import aiohttp
import yaml

from helpers.checker_helpers import (
    parse_args,
    utc_iso_now,
    resolve_dns,
    get_cert_info_blocking,
    inspect_cert,
    merge_settings,
)

REPORTS_DIR = Path("reports")
LATEST_PATH = REPORTS_DIR / "latest.json"


async def check_one(session: aiohttp.ClientSession, cfg) -> dict:
    result = {
        "name": cfg.name,
        "url": cfg.url,
        "checked_at": utc_iso_now(),
        "dns_ms": None,
        "status_code": None,
        "response_ms": None,
        "redirect_count": 0,
        "ssl": None,
        "keyword_found": None,
        "healthy": False,
        "error": None,
        "attempt": 0,
        "tags": cfg.tags,
    }

    # parse host for dns/ssl
    from urllib.parse import urlsplit

    sp = urlsplit(cfg.url)
    host = sp.hostname
    port = sp.port or (443 if sp.scheme == "https" else 80)

    attempts = cfg.retries + 1
    for attempt in range(1, attempts + 1):
        result["attempt"] = attempt
        try:
            dns_ms = await resolve_dns(host, port)
            result["dns_ms"] = int(dns_ms) if dns_ms is not None else None
        except Exception:
            result["dns_ms"] = None
        start = time.monotonic()
        try:
            timeout = aiohttp.ClientTimeout(total=cfg.timeout_seconds)
            headers = {"User-Agent": cfg.user_agent}
            async with session.get(cfg.url, timeout=timeout, headers=headers) as resp:
                status = resp.status
                text = None
                if cfg.keyword:
                    try:
                        text = await resp.text()
                    except Exception:
                        text = ""
                resp_ms = int((time.monotonic() - start) * 1000)
                result["status_code"] = int(status)
                result["response_ms"] = resp_ms
                result["redirect_count"] = len(resp.history)
                if cfg.keyword is not None:
                    result["keyword_found"] = (cfg.keyword.lower() in (text or "").lower())

                if cfg.check_ssl and cfg.url.lower().startswith("https://") and host:
                    cert = await inspect_cert(host, port, cfg.timeout_seconds)
                    result["ssl"] = cert
                else:
                    result["ssl"] = None

                status_ok = True if cfg.expected_status is None else (status == cfg.expected_status)
                latency_ok = True if cfg.max_response_ms is None else (resp_ms <= cfg.max_response_ms)
                ssl_ok = True
                if cfg.check_ssl and cfg.url.lower().startswith("https://"):
                    ssl_info = result.get("ssl")
                    ssl_ok = bool(ssl_info.get("valid") if isinstance(ssl_info, dict) else False)
                keyword_ok = True if cfg.keyword is None else (result.get("keyword_found") is True)

                result["healthy"] = bool(status_ok and latency_ok and ssl_ok and keyword_ok)
                result["error"] = None
                break
        except asyncio.TimeoutError:
            result["error"] = f"timeout after {cfg.timeout_seconds}s (attempt {attempt}/{attempts})"
        except aiohttp.ClientConnectorError as e:
            result["error"] = f"connection_error: {e}"
        except Exception as e:
            result["error"] = f"error: {e}"
        # continue retries
    return result


def _merge_settings_wrapper(global_settings: dict, u: dict):
    # helpers.merge_settings returns a simple namespace-like object
    return merge_settings(global_settings, u)


async def main() -> None:
    args = parse_args()
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"Config file not found: {cfg_path}")
        sys.exit(2)
    data = yaml.safe_load(cfg_path.read_text())
    settings = data.get("settings", {})
    urls = data.get("urls", [])

    url_cfgs = [merge_settings(settings, u) for u in urls]

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    timeout = aiohttp.ClientTimeout(total=None)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [check_one(session, uc) for uc in url_cfgs]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    # Build a richer latest payload and write both latest.json and a dated copy
    total = len(results)
    healthy_count = sum(1 for r in results if r.get("healthy"))
    resp_vals = [int(r.get("response_ms")) for r in results if r.get("response_ms") is not None]
    avg_resp = int(sum(resp_vals) / len(resp_vals)) if resp_vals else None
    latest_payload = {
        "generated_at": utc_iso_now(),
        "results": results,
        "summary": {
            "total": total,
            "healthy": healthy_count,
            "unhealthy": total - healthy_count,
            "avg_response_ms": avg_resp,
        },
        "any_unhealthy": any(r.get("healthy") is not True for r in results),
    }
    LATEST_PATH.write_text(json.dumps(latest_payload, indent=2))

    # Also persist a minimal run entry into reports/history.json so history is
    # preserved even if reporter does not run or fails. Reporter will deduplicate
    # entries by `generated_at`.
    history_path = REPORTS_DIR / "history.json"
    try:
        history = json.loads(history_path.read_text()) if history_path.exists() else []
    except Exception:
        history = []

    run_entry = {"generated_at": latest_payload["generated_at"], "urls": []}
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
    # Append only if this generated_at isn't already present
    if not any(h.get("generated_at") == run_entry["generated_at"] for h in history):
        history.append(run_entry)
        try:
            history_path.write_text(json.dumps(history, indent=2))
        except Exception:
            # Best-effort: do not fail the checker if history cannot be written
            pass

    # Note: runs are preserved in `reports/history.json` via the reporter;
    # do not create extra per-run JSON files here to avoid duplication.

    any_unhealthy = False
    for r in results:
        name = r["name"][:18].ljust(18)
        code = str(r.get("status_code") or "—")
        resp = (f"{r.get('response_ms')}ms" if r.get("response_ms") is not None else "—")
        dns = (f"{r.get('dns_ms')}ms" if r.get("dns_ms") is not None else "—")
        ssl_info = "—"
        if r.get("ssl") and isinstance(r.get("ssl"), dict) and r["ssl"].get("expires_in_days") is not None:
            ssl_info = f"{r['ssl']['expires_in_days']}d remaining"
        err = r.get("error")
        tag = "OK" if r.get("healthy") else "FAIL"
        print(f"[{tag}] {name} {code:>4}   {resp:>7}  DNS: {dns:>6}  {err or 'SSL: ' + ssl_info}")
        if not r.get("healthy"):
            any_unhealthy = True

    # Default behavior: do not fail the process — this checker is an analyzer and should
    # allow downstream reporter/alerter steps to run. If the user explicitly requests
    # strict failure (for local debugging), allow that via `--fail-on-unhealthy`.
    if getattr(args, "fail_on_unhealthy", False):
        sys.exit(1 if any_unhealthy else 0)
    return


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(2)
