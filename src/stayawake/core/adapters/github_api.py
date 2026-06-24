#!/usr/bin/env python3
"""GitHub REST adapter (stdlib urllib only).

Single responsibility: talk to the GitHub API. Used by the availability alerter
(issues/search) and by the security feature (repo enumeration).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

_API = "https://api.github.com"


def request(path: str, method: str = "GET", token: str | None = None,
            data: dict | None = None) -> Any:
    """Low-level call. `path` is the API path (leading slash)."""
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "StayAwakeBot/1.0"}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(_API + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as he:
        try:
            detail = he.read().decode()
        except Exception:
            detail = str(he)
        print(f"GitHub API error: {he.code} {detail}")
        return None
    except Exception as e:  # noqa: BLE001
        print(f"GitHub API request failed: {e}")
        return None


def list_repos(account: str, kind: str, token: str | None,
               include_forks: bool = False, include_archived: bool = False) -> list[str]:
    """Return ['owner/name', ...] for a user or org, paginated."""
    base = "users" if kind == "users" else "orgs"
    slugs: list[str] = []
    page = 1
    while True:
        batch = request(f"/{base}/{account}/repos?per_page=100&page={page}&type=all", token=token)
        if not isinstance(batch, list) or not batch:
            break
        for r in batch:
            if (not include_forks and r.get("fork")) or (not include_archived and r.get("archived")):
                continue
            if r.get("full_name"):
                slugs.append(r["full_name"])
        if len(batch) < 100:
            break
        page += 1
    return slugs


def list_installation_repos(token: str | None, include_archived: bool = False) -> list[str]:
    """Repos a GitHub App installation can access ('owner/name', ...), paginated.
    `token` must be an installation access token (see core.github_app)."""
    slugs: list[str] = []
    page = 1
    while True:
        res = request(f"/installation/repositories?per_page=100&page={page}", token=token)
        repos = res.get("repositories") if isinstance(res, dict) else None
        if not repos:
            break
        for r in repos:
            if not include_archived and r.get("archived"):
                continue
            if r.get("full_name"):
                slugs.append(r["full_name"])
        if len(repos) < 100:
            break
        page += 1
    return slugs


def list_open_pulls(owner: str, repo: str, head_branch: str, token: str | None) -> list[dict]:
    """Open PRs whose head is `owner:head_branch` (used for de-duplication)."""
    res = request(f"/repos/{owner}/{repo}/pulls?state=open&head={owner}:{head_branch}",
                  token=token)
    return res if isinstance(res, list) else []


def create_pull(owner: str, repo: str, title: str, head: str, base: str,
                body: str, token: str | None) -> dict | None:
    """Open a PR. Returns the created PR dict (with 'number','html_url') or None."""
    return request(f"/repos/{owner}/{repo}/pulls", method="POST", token=token,
                   data={"title": title, "head": head, "base": base, "body": body})


def get_branch_protection(owner: str, repo: str, branch: str,
                          token: str | None) -> dict | None:
    """Branch-protection settings for a branch, or None if unprotected/inaccessible.
    Quiet on errors (a 404 is the common 'not protected' case)."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "StayAwakeBot/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{_API}/repos/{owner}/{repo}/branches/{branch}/protection",
        headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001 — 404/403/network all mean "treat as unprotected"
        return None
