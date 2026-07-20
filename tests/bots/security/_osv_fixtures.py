#!/usr/bin/env python3
"""Shared helpers for the offline-advisory-corpus tests (#1120): build a synthetic OSV export zip
in memory so the tests exercise the real parse → filter → cache → load → match pipeline without
touching the network."""
from __future__ import annotations

import io
import json
import zipfile
from typing import Any


def osv_zip(members: dict[str, dict[str, Any]]) -> bytes:
    """`{member_name.json: osv_record_dict}` → the bytes of an OSV `all.zip` export."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, rec in members.items():
            zf.writestr(name, json.dumps(rec))
    return buf.getvalue()


def mal_record(name: str, versions: list[str], *, rid: str = "MAL-2024-0001",
               ecosystem: str = "npm", aliases: list[str] | None = None) -> dict[str, Any]:
    """A minimal malicious OSV record (MAL- id) naming one package with explicit versions."""
    return {"id": rid, "aliases": list(aliases or []),
            "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                          "versions": list(versions)}]}


def vuln_record(name: str, versions: list[str] | None = None, *, rid: str = "CVE-2024-0001",
                ecosystem: str = "npm", aliases: list[str] | None = None,
                ranges: list[tuple[str, str | None]] | None = None,
                range_type: str = "SEMVER") -> dict[str, Any]:
    """A minimal ordinary-vulnerability OSV record (no malware signals) — the advisory tier.

    `ranges` is `[(introduced, fixed_or_None), …]` → an OSV `ranges` entry, so a test can exercise the
    remediation path (the `fixed` event that becomes the upgrade target, #1252)."""
    affected: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name}}
    if versions:
        affected["versions"] = list(versions)
    if ranges:
        affected["ranges"] = [
            {"type": range_type,
             "events": [{"introduced": intro}] + ([{"fixed": fix}] if fix else [])}
            for intro, fix in ranges]
    return {"id": rid, "aliases": list(aliases or []), "affected": [affected]}
