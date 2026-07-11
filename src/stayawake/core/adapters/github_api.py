#!/usr/bin/env python3
"""GitHub REST adapter (stdlib urllib only).

Single responsibility: talk to the GitHub API. Used by the availability alerter
(issues/search) and by the security feature (repo enumeration).
"""
from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any

_API = "https://api.github.com"

# Verify TLS against a real CA bundle. Python's default context trusts the OS store, which on
# common macOS (python.org) builds isn't wired to OpenSSL — so every call dies with
# CERTIFICATE_VERIFY_FAILED. certifi ships a portable bundle; fall back to the system default
# if it's somehow absent (the dependency makes that unlikely).
try:
    import certifi
    _SSL_CTX: ssl.SSLContext = ssl.create_default_context(cafile=certifi.where())
except Exception:  # noqa: BLE001 — a TLS-setup hiccup must never crash import
    _SSL_CTX = ssl.create_default_context()


def request(path: str, method: str = "GET", token: str | None = None,
            data: dict | None = None, quiet: bool = False) -> Any:
    """Low-level call. `path` is the API path (leading slash). `quiet` suppresses error
    logging (e.g. expected 404s while polling for an async fork to become available)."""
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
        with urllib.request.urlopen(req, timeout=15, context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as he:
        if not quiet:
            try:
                detail = he.read().decode()
            except Exception:
                detail = str(he)
            # stderr, never stdout — stdout carries `saw scan --json` / piped report output.
            print(f"GitHub API error: {he.code} {detail}", file=sys.stderr)
        return None
    except Exception as e:  # noqa: BLE001
        if not quiet:
            print(f"GitHub API request failed: {e}", file=sys.stderr)
        return None


def get_authenticated_user(token: str | None, quiet: bool = False) -> dict | None:
    """The account the token belongs to (its 'login' is the fork owner). None on failure.

    NOTE: `GET /user` is `enabledForGitHubApps: false` in GitHub's API — a GitHub App
    **installation** token (which the Actions `GITHUB_TOKEN` is) is FORBIDDEN from it and
    gets `403 Resource not accessible by integration`. So this returns None for an installation
    token even when the token is perfectly valid. Callers that must accept installation tokens
    should use `token_is_valid()` (validation) rather than gating on this. Pass `quiet=True` to
    suppress the error log when a 403 here is expected (e.g. the preflight probe)."""
    res = request("/user", token=token, quiet=quiet)
    return res if isinstance(res, dict) else None


def token_is_valid(token: str | None, repo_slug: str | None = None) -> bool:
    """Is `token` live and accepted by GitHub — WITHOUT requiring user-to-server scope?

    The preflight before any push must accept BOTH a personal access token and the Actions
    `GITHUB_TOKEN` (a GitHub App installation token). It can't just call `GET /user`: that is
    `enabledForGitHubApps: false`, so an installation token 403s there even though it's valid.
    Instead, probe endpoints an installation token CAN reach (both `enabledForGitHubApps: true`):

      1. `GET /user` — greenlights a genuine user token / PAT (an installation token 403s → skip).
      2. If a repo context is known (`repo_slug`, e.g. `$GITHUB_REPOSITORY` under Actions):
         `GET /repos/{owner}/{repo}` is the check — it needs only `metadata:read` (always granted),
         so a live installation token passes AND a token that can't reach the repo is rejected.
         This is authoritative when we have a repo, so we do NOT also fall through to (3): if
         get_repo failed it's either no-access (reject) or the API is down (a second probe would
         only add another timeout).
      3. No repo context (an App token used outside Actions): `GET /rate_limit` as a pure liveness
         floor.

    Fail-CLOSED by construction: GitHub validates the token BEFORE resource visibility, so a
    bogus/expired token gets 401 on every probe (even on a public repo) → None → False; an empty
    token or an unreachable/broken-TLS API likewise yields None → False (so the preflight still
    catches the SSL case it was built for). At most two probes run, so a total outage fails in
    ≤2×timeout. Only a genuinely live, GitHub-accepted token returns True. Like the old `/user`
    gate, this asserts the token is live+accepted (and, when a repo is known, reachable) — not that
    it has write scope; the push handles that, via the fork/patch/issue fallback ladder."""
    if not token:
        return False
    if get_authenticated_user(token, quiet=True) is not None:
        return True
    if repo_slug and "/" in repo_slug:
        owner, name = repo_slug.split("/", 1)
        return get_repo(owner, name, token) is not None
    return request("/rate_limit", token=token, quiet=True) is not None


def get_repo(owner: str, repo: str, token: str | None) -> dict | None:
    """A repo object, or None if it doesn't exist yet (quiet — used to poll a new fork)."""
    res = request(f"/repos/{owner}/{repo}", token=token, quiet=True)
    return res if isinstance(res, dict) else None


def create_fork(owner: str, repo: str, token: str | None, quiet: bool = False) -> dict | None:
    """Fork a repo under the authenticated account (idempotent: returns the existing fork
    if present). Creation is asynchronous — poll get_repo() for readiness. Returns the
    fork object (with 'full_name') or None if forking isn't permitted. `quiet` suppresses
    error logging — the remediation fallback EXPECTS a 403 (forking disabled) and reports
    the outcome itself, so the raw error mustn't collide with a progress spinner."""
    res = request(f"/repos/{owner}/{repo}/forks", method="POST", token=token, quiet=quiet)
    return res if isinstance(res, dict) else None


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


def list_my_repos(token: str | None, include_forks: bool = False,
                  include_archived: bool = False, affiliation: str = "owner") -> list[str]:
    """Repos the AUTHENTICATED user owns ('owner/name', ...), paginated. Uses `/user/repos`
    — which is **private-inclusive** — NOT `/users/{me}/repos`, which returns only PUBLIC
    repos even with your token (so the latter would silently miss your private repos). Default
    `affiliation='owner'` (just yours); pass `'owner,collaborator,organization_member'` for
    everything you can touch."""
    slugs: list[str] = []
    page = 1
    while True:
        batch = request(f"/user/repos?per_page=100&page={page}&affiliation={affiliation}", token=token)
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


def list_open_pulls(owner: str, repo: str, head_branch: str, token: str | None,
                    head_owner: str | None = None) -> list[dict]:
    """Open PRs on `owner/repo` whose head is `<head_owner>:head_branch` (for de-dup).
    `head_owner` defaults to `owner` (same-repo PRs); pass the fork owner for cross-fork."""
    ho = head_owner or owner
    res = request(f"/repos/{owner}/{repo}/pulls?state=open&head={ho}:{head_branch}",
                  token=token)
    return res if isinstance(res, list) else []


def create_pull(owner: str, repo: str, title: str, head: str, base: str,
                body: str, token: str | None) -> dict | None:
    """Open a PR. Returns the created PR dict (with 'number','html_url') or None."""
    return request(f"/repos/{owner}/{repo}/pulls", method="POST", token=token,
                   data={"title": title, "head": head, "base": base, "body": body})


def close_pull(owner: str, repo: str, number: int, token: str | None) -> dict | None:
    """Close an open PR (PATCH state=closed) — used by `saw discard --pr`. Returns the
    updated PR dict or None. (Deleting the head branch also auto-closes a PR, so the
    `discard --branch` path doesn't need this.)"""
    return request(f"/repos/{owner}/{repo}/pulls/{number}", method="PATCH", token=token,
                   data={"state": "closed"})


def list_open_issues(owner: str, repo: str, token: str | None,
                     labels: str | None = None, quiet: bool = False) -> list[dict]:
    """Open issues (PRs filtered out), optionally restricted to a label. Used to
    de-duplicate the remediation issue fallback."""
    path = f"/repos/{owner}/{repo}/issues?state=open&per_page=100"
    if labels:
        path += f"&labels={labels}"
    res = request(path, token=token, quiet=quiet)
    # The issues endpoint also returns PRs; real issues lack a 'pull_request' key.
    return [i for i in res if isinstance(i, dict) and "pull_request" not in i] \
        if isinstance(res, list) else []


def create_issue(owner: str, repo: str, title: str, body: str, token: str | None,
                 labels: list[str] | None = None, quiet: bool = False) -> dict | None:
    """Open an issue. Returns the created issue dict (with 'number','html_url') or None.
    `quiet` suppresses error logging — the issue fallback expects a possible 403 (no
    issues/label permission) and reports the patch outcome itself."""
    data: dict = {"title": title, "body": body}
    if labels:
        data["labels"] = labels
    return request(f"/repos/{owner}/{repo}/issues", method="POST", token=token, data=data, quiet=quiet)


def update_issue(owner: str, repo: str, number: int, token: str | None,
                 title: str | None = None, body: str | None = None,
                 state: str | None = None) -> dict | None:
    """PATCH an existing issue (title/body/state). Editing the body sends NO
    notification — used to refresh a self-updating status issue silently."""
    data: dict = {}
    if title is not None:
        data["title"] = title
    if body is not None:
        data["body"] = body
    if state is not None:
        data["state"] = state
    if not data:
        return None
    return request(f"/repos/{owner}/{repo}/issues/{number}", method="PATCH",
                   token=token, data=data)


def add_issue_comment(owner: str, repo: str, number: int, body: str,
                      token: str | None) -> dict | None:
    """POST a comment (this DOES notify subscribers — reserve for state changes)."""
    return request(f"/repos/{owner}/{repo}/issues/{number}/comments", method="POST",
                   token=token, data={"body": body})


def find_issue_by_marker(owner: str, repo: str, marker: str, token: str | None,
                         labels: str | None = None) -> dict | None:
    """Find one open issue whose body contains `marker` (a stable hidden tag), so the
    sentinel can update its single per-project issue regardless of title/status churn."""
    for it in list_open_issues(owner, repo, token, labels=labels):
        if marker in (it.get("body") or ""):
            return it
    return None


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
        with urllib.request.urlopen(req, timeout=15, context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001 — 404/403/network all mean "treat as unprotected"
        return None
