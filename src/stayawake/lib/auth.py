#!/usr/bin/env python3
"""GitHub credential resolution.

Preference order (highest first):
  1. GH_SECURITY_TOKEN / GITHUB_TOKEN in the environment (CI and explicit overrides).
  2. The user's GitHub CLI session (`gh auth token`) — short-lived and never persisted
     by us, which is exactly what the hygiene audit recommends over a cached PAT.

Local scanning needs NO credential; this is only for cloning private remotes and for
writes (PRs, issues, branch-protection reads). Every gh probe degrades gracefully:
a gh that is missing, not logged in, slow, or erroring never raises — it just yields
no token, and callers either fall back (anonymous public read) or print an actionable
hint. Stdlib only. Tokens are returned to callers but never logged here.
"""
from __future__ import annotations

import shutil
import subprocess
import sys

from stayawake.utils import env

ENV_VARS = (env.GH_SECURITY_TOKEN, env.GITHUB_TOKEN)
_GH_TIMEOUT = 10  # gh auth token is a local keyring read; should be near-instant.


def gh_path() -> str | None:
    """Absolute path to the GitHub CLI, or None if it isn't installed / on PATH."""
    return shutil.which("gh")


def gh_installed() -> bool:
    return gh_path() is not None


def _env_token() -> tuple[str | None, str | None]:
    for var in ENV_VARS:
        val = env.get(var)   # strips; empty/whitespace → None
        if val:
            return val, var
    return None, None


def gh_token(hostname: str = "github.com") -> str | None:
    """A short-lived token from the gh session, or None. Never raises.

    Handles every edge case: gh not installed, gh present but not logged in (non-zero
    exit), empty output, a hung gh (timeout), an old gh without --hostname (retry
    plain), and OS-level spawn errors."""
    if not gh_installed():
        return None
    for argv in (["gh", "auth", "token", "--hostname", hostname], ["gh", "auth", "token"]):
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=_GH_TIMEOUT, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode == 0:
            token = (proc.stdout or "").strip()
            if token:
                return token
    return None


def _app_token(repo_slug: str | None = None) -> str | None:
    """A GitHub App installation token, or None if no App is configured. NEVER raises:
    a configured-but-broken App (bad/encrypted key, unreachable API, or any other failure) is
    reported to stderr and treated as 'no token' so resolution falls through to the gh session —
    exactly like `gh_token`. Diagnostics go to STDERR so they never pollute a command's stdout
    (e.g. a piped scan report). (#1287)

    When `repo_slug` is given, the token is minted from the installation that OWNS that repo
    (multi-account) — see `github_app.installation_token`."""
    from stayawake.lib import github_app  # lazy import: keeps App auth off the hot path
    try:
        return github_app.installation_token(repo_slug)
    except github_app.GithubAppError as e:
        print(f"GitHub App auth configured but unavailable: {e}", file=sys.stderr)
        return None
    except Exception as e:  # noqa: BLE001 — a broken App must NEVER crash credential resolution
        print(f"GitHub App auth error (ignored, falling back): {e}", file=sys.stderr)
        return None


def resolve_token(hostname: str = "github.com",
                  *, repo_slug: str | None = None) -> tuple[str | None, str | None]:
    """Return (token, source). `source` is the env var name, 'github-app', 'gh', or None.

    Precedence: an explicit env PAT wins (human override) → a GitHub App installation
    token (automation default) → the gh CLI session → none. Callers decide whether a
    missing token is fatal (writes) or fine (public read).

    `repo_slug` ("owner/repo") makes the App path mint the token from the installation that OWNS
    that repo (multi-account). It does NOT affect the env-PAT / gh paths, which are repo-agnostic."""
    token, source = _env_token()
    if token:
        return token, source
    app = _app_token(repo_slug)
    if app:
        return app, "github-app"
    token = gh_token(hostname)
    if token:
        return token, "gh"
    return None, None


def act_token(base_token: str | None, source: str | None,
              repo_slug: str | None) -> tuple[str | None, str | None]:
    """The token to ACT on one specific `repo_slug` during a multi-repo sweep, plus an optional
    per-repo error string. Resolve the base credential ONCE (so a sweep does not re-spawn `gh` per
    repo); then upgrade PER REPO only for a GitHub App — minting the token of the installation that
    owns that repo (multi-account) so each repo is acted on with the right account's credentials.
    env-PAT / gh sessions are repo-agnostic and returned unchanged.

    Never raises: an App that is configured but cannot reach the repo yields `(None, guidance)` so the
    caller records it as that repo's outcome and keeps the sweep going."""
    if source == "github-app" and repo_slug and "/" in repo_slug:
        from stayawake.lib import github_app
        try:
            return github_app.installation_token(repo_slug), None
        except github_app.GithubAppError as e:
            return None, str(e)
        except Exception as e:  # noqa: BLE001 — one repo's auth hiccup must not abort the sweep
            return None, str(e)
    return base_token, None


def no_credential_hint(action: str = "this operation") -> str:
    """Actionable, gh-aware guidance to print when a required credential is missing.

    Names the single token a user configures (GH_SECURITY_TOKEN); the automatic Actions
    GITHUB_TOKEN isn't something to set up, so we don't tell people to."""
    var = ENV_VARS[0]  # GH_SECURITY_TOKEN — the one credential a user configures
    if not gh_installed():
        return (f"No GitHub credential for {action}. Either install the GitHub CLI "
                f"(https://cli.github.com) and run `gh auth login`, or set {var} "
                f"to a token with the required scope.")
    return (f"No GitHub credential for {action}. Run `gh auth login` "
            f"(check with `gh auth status`), or set {var} to a token with the required scope.")
