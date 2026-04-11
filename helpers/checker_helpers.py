#!/usr/bin/env python3
import argparse
import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any


def parse_args():
    p = argparse.ArgumentParser(description="StayAwakeBot async URL health checker")
    p.add_argument("--config", default="config/urls.yml", help="Path to config YAML")
    p.add_argument("--fail-on-unhealthy", action="store_true", help="Exit with non-zero if any URL is unhealthy (opt-in)")
    return p.parse_args()


def utc_iso_now():
    return datetime.now(timezone.utc).astimezone().isoformat()


async def resolve_dns(host: str, port: int, loop: asyncio.AbstractEventLoop | None = None) -> int:
    start = time.monotonic()
    try:
        if loop is None:
            loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, socket.getaddrinfo, host, port)
        return int((time.monotonic() - start) * 1000)
    except Exception:
        return int((time.monotonic() - start) * 1000)


def get_cert_info_blocking(host: str, port: int, timeout: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp = exp.replace(tzinfo=timezone.utc)
                        delta = exp - datetime.now(timezone.utc)
                        expires_in_days = max(0, int(delta.total_seconds() / 86400))
                        valid = delta.total_seconds() > 0
                        return {"valid": valid, "expires_in_days": expires_in_days, "error": None}
                    except Exception as e:
                        return {"valid": False, "expires_in_days": None, "error": f"parse_error: {e}"}
                else:
                    return {"valid": False, "expires_in_days": None, "error": "no_notAfter"}
    except Exception as e:
        return {"valid": False, "expires_in_days": None, "error": str(e)}


async def inspect_cert(host: str, port: int, timeout: int):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_cert_info_blocking, host, port, timeout)


def merge_settings(global_settings: dict, u: dict) -> Any:
    timeout_seconds = u.get("timeout_seconds", global_settings.get("timeout_seconds", 10))
    retries = u.get("retries", global_settings.get("retries", 0))
    user_agent = global_settings.get("user_agent", "StayAwakeBot/1.0")
    alert_on_failure = global_settings.get("alert_on_failure", True)
    alert_on_recovery = global_settings.get("alert_on_recovery", True)
    consecutive_failures_before_alert = global_settings.get("consecutive_failures_before_alert", 1)

    # Build a simple namespace object similar to original URLConfig
    @dataclass
    class URLCfg:
        name: str
        url: str
        expected_status: int | None
        max_response_ms: int | None
        check_ssl: bool
        keyword: str | None
        tags: list[str]
        timeout_seconds: int
        retries: int
        user_agent: str
        alert_on_failure: bool
        alert_on_recovery: bool
        consecutive_failures_before_alert: int

    return URLCfg(
        name=u["name"],
        url=u["url"],
        expected_status=u.get("expected_status", None),
        max_response_ms=u.get("max_response_ms", None),
        check_ssl=u.get("check_ssl", False),
        keyword=u.get("keyword", None),
        tags=u.get("tags", []),
        timeout_seconds=int(timeout_seconds),
        retries=int(retries),
        user_agent=user_agent,
        alert_on_failure=alert_on_failure,
        alert_on_recovery=alert_on_recovery,
        consecutive_failures_before_alert=int(consecutive_failures_before_alert),
    )
