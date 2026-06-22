#!/usr/bin/env python3
"""HTTP/DNS/TLS probing adapter for the availability feature.

Single responsibility: talk to the network. Pure-ish helpers the checker uses;
no reporting or alerting logic here.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone


async def resolve_dns(host: str, port: int,
                      loop: asyncio.AbstractEventLoop | None = None) -> int:
    start = time.monotonic()
    try:
        loop = loop or asyncio.get_running_loop()
        await loop.run_in_executor(None, socket.getaddrinfo, host, port)
    except Exception:
        pass
    return int((time.monotonic() - start) * 1000)


def get_cert_info_blocking(host: str, port: int, timeout: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                not_after = cert.get("notAfter")
                if not not_after:
                    return {"valid": False, "expires_in_days": None, "error": "no_notAfter"}
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                delta = exp - datetime.now(timezone.utc)
                return {
                    "valid": delta.total_seconds() > 0,
                    "expires_in_days": max(0, int(delta.total_seconds() / 86400)),
                    "error": None,
                }
    except Exception as e:  # noqa: BLE001 — surface any TLS/socket failure as data
        return {"valid": False, "expires_in_days": None, "error": str(e)}


async def inspect_cert(host: str, port: int, timeout: int) -> dict:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_cert_info_blocking, host, port, timeout)
