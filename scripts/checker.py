#!/usr/bin/env python3
"""Async URL health checker for StayAwakeBot

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
            _ = await resolve_dns(host, port)
        except Exception:
            pass
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

    LATEST_PATH.write_text(json.dumps({"generated_at": utc_iso_now(), "results": results}, indent=2))

    any_unhealthy = False
    for r in results:
        name = r["name"][:18].ljust(18)
        code = str(r.get("status_code") or "—")
        resp = (f"{r.get('response_ms')}ms" if r.get("response_ms") is not None else "—")
        ssl_info = "—"
        if r.get("ssl") and isinstance(r.get("ssl"), dict) and r["ssl"].get("expires_in_days") is not None:
            ssl_info = f"{r['ssl']['expires_in_days']}d remaining"
        err = r.get("error")
        tag = "OK" if r.get("healthy") else "FAIL"
        print(f"[{tag}] {name} {code:>4}   {resp:>7}  {err or 'SSL: ' + ssl_info}")
        if not r.get("healthy"):
            any_unhealthy = True

    sys.exit(1 if any_unhealthy else 0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(2)
