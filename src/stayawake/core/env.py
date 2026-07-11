#!/usr/bin/env python3
"""The one place stayawake reads the process environment.

Every environment variable the app consults is NAMED and READ here — so there are no
magic-string `os.environ.get("…")` calls scattered across modules, the full env surface is
discoverable in a single file, and a test can steer behaviour by patching one module. Domain
logic that happens to consult env (token precedence in `core.auth`, GitHub App auth in
`core.github_app`) keeps its own logic and just reads names/values from here.

Note: `get()` strips surrounding whitespace and treats an empty/whitespace value as unset, so a
variable is "set" only when it holds real content — consistent across every toggle and path.
Stdlib only; imported widely, so it must stay dependency-light and import-cheap.
"""
from __future__ import annotations

import os

# ── variable names (single source of truth) ───────────────────────────────────────────
# GitHub credentials / Actions context
GH_SECURITY_TOKEN = "GH_SECURITY_TOKEN"   # the one PAT a user configures (see core.auth)
GITHUB_TOKEN = "GITHUB_TOKEN"             # auto-minted by GitHub Actions (installation token)
GITHUB_REPOSITORY = "GITHUB_REPOSITORY"   # "owner/name", set by GitHub Actions
SLACK_WEBHOOK_URL = "SLACK_WEBHOOK_URL"
# app directories / behaviour
STAYAWAKE_REPORTS_DIR = "STAYAWAKE_REPORTS_DIR"
SAW_ADVISORY_CACHE_DIR = "SAW_ADVISORY_CACHE_DIR"
XDG_CACHE_HOME = "XDG_CACHE_HOME"
NO_COLOR = "NO_COLOR"
PAGER = "PAGER"
# any of these set (to a non-empty value) disables live streaming
NO_STREAM = ("STAYAWAKE_NO_STREAM", "NO_STREAM")


def get(name: str, default: str | None = None) -> str | None:
    """Read one variable — the ONLY place `os.environ` is touched for app config. Strips
    surrounding whitespace and treats an empty/whitespace value as unset (→ `default`)."""
    val = os.environ.get(name)
    if val is None:
        return default
    val = val.strip()
    return val or default


def any_set(names) -> bool:
    """True when any of `names` holds a non-empty value (e.g. the NO_STREAM group)."""
    return any(get(n) for n in names)


# ── GitHub / Slack context (reused across the alerters + the remediator) ───────────────
def github_token() -> str | None:
    return get(GITHUB_TOKEN)


def github_repository() -> str | None:
    return get(GITHUB_REPOSITORY)


def github_slug() -> tuple[str, str] | None:
    """`(owner, name)` parsed from `GITHUB_REPOSITORY`, or None when unset or malformed — the
    single home for the `owner, name = repo.split('/', 1)` split several callers duplicated."""
    repo = github_repository()
    if repo and "/" in repo:
        owner, name = repo.split("/", 1)
        if owner and name:
            return owner, name
    return None


def slack_webhook() -> str | None:
    return get(SLACK_WEBHOOK_URL)


# ── behaviour toggles ──────────────────────────────────────────────────────────────────
def no_color() -> bool:
    """The NO_COLOR convention: any non-empty value disables colour output."""
    return bool(get(NO_COLOR))


def stream_disabled() -> bool:
    """Live streaming is off when any NO_STREAM variable is set."""
    return any_set(NO_STREAM)
