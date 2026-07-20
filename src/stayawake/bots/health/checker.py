#!/usr/bin/env python3
"""Availability checking logic (per-URL probe + payload assembly).

Single responsibility: turn UrlCheckConfig objects into result dicts and the
`latest.json` payload. Network access is delegated to adapters.http_client.
"""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

import aiohttp

from stayawake.core.adapters.http_client import resolve_dns, inspect_cert
from stayawake.utils.timeutil import now_iso
from stayawake.bots.health.models import UrlCheckConfig


async def check_one(session: aiohttp.ClientSession, cfg: UrlCheckConfig) -> dict:
    result = {
        "name": cfg.name, "url": cfg.url, "checked_at": now_iso(),
        "dns_ms": None, "status_code": None, "response_ms": None,
        "redirect_count": 0, "ssl": None, "keyword_found": None,
        "healthy": False, "error": None, "reason": None, "attempt": 0, "tags": cfg.tags,
    }
    sp = urlsplit(cfg.url)
    host = sp.hostname
    port = sp.port or (443 if sp.scheme == "https" else 80)

    attempts = cfg.retries + 1
    for attempt in range(1, attempts + 1):
        result["attempt"] = attempt
        try:
            result["dns_ms"] = int(await resolve_dns(host, port)) if host else None
        except Exception:
            result["dns_ms"] = None
        start = time.monotonic()
        try:
            timeout = aiohttp.ClientTimeout(total=cfg.timeout_seconds)
            headers = {"User-Agent": cfg.user_agent}
            async with session.get(cfg.url, timeout=timeout, headers=headers) as resp:
                text = await resp.text() if cfg.keyword else None
                resp_ms = int((time.monotonic() - start) * 1000)
                result["status_code"] = int(resp.status)
                result["response_ms"] = resp_ms
                result["redirect_count"] = len(resp.history)
                if cfg.keyword is not None:
                    result["keyword_found"] = cfg.keyword.lower() in (text or "").lower()

                if cfg.check_ssl and cfg.url.lower().startswith("https://") and host:
                    result["ssl"] = await inspect_cert(host, port, cfg.timeout_seconds)

                status_ok = cfg.expected_status is None or resp.status == cfg.expected_status
                latency_ok = cfg.max_response_ms is None or resp_ms <= cfg.max_response_ms
                ssl_ok = True
                if cfg.check_ssl and cfg.url.lower().startswith("https://"):
                    info = result.get("ssl")
                    ssl_ok = bool(info.get("valid") if isinstance(info, dict) else False)
                keyword_ok = cfg.keyword is None or result.get("keyword_found") is True

                result["healthy"] = bool(status_ok and latency_ok and ssl_ok and keyword_ok)
                result["error"] = None
                break
        except asyncio.TimeoutError:
            result["error"] = f"timeout after {cfg.timeout_seconds}s (attempt {attempt}/{attempts})"
        except aiohttp.ClientConnectorError as e:
            result["error"] = f"connection_error: {e}"
        except Exception as e:  # noqa: BLE001
            result["error"] = f"error: {e}"
    result["reason"] = None if result["healthy"] else _derive_reason(result, cfg)
    return result


def _derive_reason(result: dict, cfg: UrlCheckConfig) -> str:
    """Human-readable explanation of WHY a check is unhealthy (named per failing
    dimension), so an alert can say 'keyword not found' rather than a bare 'DOWN'."""
    if result.get("error"):
        return result["error"]
    parts: list[str] = []
    sc = result.get("status_code")
    if cfg.expected_status is not None and sc is not None and sc != cfg.expected_status:
        parts.append(f"HTTP {sc} (expected {cfg.expected_status})")
    rm = result.get("response_ms")
    if cfg.max_response_ms is not None and rm is not None and rm > cfg.max_response_ms:
        parts.append(f"slow: {rm}ms > {cfg.max_response_ms}ms")
    if cfg.keyword is not None and result.get("keyword_found") is False:
        parts.append(f"keyword '{cfg.keyword}' not found in body")
    if cfg.check_ssl and cfg.url.lower().startswith("https://"):
        info = result.get("ssl")
        if not (isinstance(info, dict) and info.get("valid")):
            parts.append("TLS certificate invalid or expired")
    if sc is None and not parts:
        parts.append("no response")
    return "; ".join(parts) or "unhealthy"


async def run_checks(configs: list[UrlCheckConfig]) -> list[dict]:
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    timeout = aiohttp.ClientTimeout(total=None)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        return await asyncio.gather(*(check_one(session, c) for c in configs))


def format_console_line(r: dict) -> str:
    name = r["name"][:18].ljust(18)
    code = str(r.get("status_code") or "—")
    resp = f"{r.get('response_ms')}ms" if r.get("response_ms") is not None else "—"
    dns = f"{r.get('dns_ms')}ms" if r.get("dns_ms") is not None else "—"
    ssl_info = "—"
    if isinstance(r.get("ssl"), dict) and r["ssl"].get("expires_in_days") is not None:
        ssl_info = f"{r['ssl']['expires_in_days']}d remaining"
    tag = "OK" if r.get("healthy") else "FAIL"
    return f"[{tag}] {name} {code:>4}   {resp:>7}  DNS: {dns:>6}  {r.get('error') or 'SSL: ' + ssl_info}"
