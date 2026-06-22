#!/usr/bin/env python3
"""Minimal GitHub REST helper (stdlib urllib only) for repo enumeration.

Single responsibility: list repositories for users/orgs so RemoteRepoTarget can
clone them. Read-only; never mutates anything.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

_API = "https://api.github.com"


def _get(path: str, token: str | None) -> Any:
    req = urllib.request.Request(_API + path)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "StayAwakeBot-Security/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return None


def list_repos(account: str, kind: str, token: str | None,
               include_forks: bool = False, include_archived: bool = False) -> list[str]:
    """Return ['owner/name', ...] for a user or org, paginated."""
    base = "users" if kind == "users" else "orgs"
    slugs: list[str] = []
    page = 1
    while True:
        batch = _get(f"/{base}/{account}/repos?per_page=100&page={page}&type=all", token)
        if not isinstance(batch, list) or not batch:
            break
        for r in batch:
            if not include_forks and r.get("fork"):
                continue
            if not include_archived and r.get("archived"):
                continue
            full = r.get("full_name")
            if full:
                slugs.append(full)
        if len(batch) < 100:
            break
        page += 1
    return slugs
