#!/usr/bin/env python3
"""GitHub App authentication — mint short-lived installation tokens.

Optional feature: needs `pip install "stayawake[app]"` (PyJWT[crypto]). A GitHub App is
the production way to scan/remediate org-wide: an admin installs it once on selected
repos and it mints **1-hour, auto-rotating installation tokens** scoped to exactly the
granted permissions — no human PAT to leak, fully revocable, and the install itself
defines scope.

Security: the private key stays **in memory** (never written to disk); JWT signing is
delegated to the audited PyJWT/cryptography stack. Tokens/keys are returned to callers
but never logged here.

Configuration (env only):
  GH_APP_ID                 numeric App ID (not secret)
  GH_APP_PRIVATE_KEY        PEM contents of the App private key (secret), OR
  GH_APP_PRIVATE_KEY_PATH   path to the .pem
  GH_APP_INSTALLATION_ID    optional; if omitted and the App has exactly one
                            installation, that one is used
"""
from __future__ import annotations

import os
import time
from datetime import datetime
from pathlib import Path

from stayawake.lib.adapters import github_api

APP_ID_ENV = "GH_APP_ID"
PRIVATE_KEY_ENV = "GH_APP_PRIVATE_KEY"
PRIVATE_KEY_PATH_ENV = "GH_APP_PRIVATE_KEY_PATH"
INSTALLATION_ID_ENV = "GH_APP_INSTALLATION_ID"

_SKEW = 60          # refresh this many seconds before the API-stated expiry
_JWT_TTL = 540      # App JWT lifetime (≤ 10 min per GitHub)
# (app_id, installation_env) -> (installation_token, expires_epoch)
_cache: dict[tuple[str, str], tuple[str, float]] = {}


class GithubAppError(RuntimeError):
    """App auth is configured but cannot be completed (missing extra, bad key, no
    resolvable installation, API failure)."""


def _private_key() -> str | None:
    pem = os.environ.get(PRIVATE_KEY_ENV)
    if pem and pem.strip():
        return pem
    path = os.environ.get(PRIVATE_KEY_PATH_ENV)
    if path:
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError:
            return None
    return None


def is_configured() -> bool:
    """True if a GitHub App is configured (App ID + a private-key source present)."""
    return bool(os.environ.get(APP_ID_ENV) and _private_key())


def _build_jwt(app_id: str, private_key: str) -> str:
    """Sign the App JWT (RS256). Requires the optional PyJWT[crypto] extra."""
    try:
        import jwt  # PyJWT — only needed for App auth (optional [app] extra)
    except ImportError as e:
        raise GithubAppError(
            'GitHub App auth needs PyJWT — install the extra: pip install "stayawake[app]".'
        ) from e
    now = int(time.time())
    payload = {"iat": now - _SKEW, "exp": now + _JWT_TTL, "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


def _expiry_epoch(expires_at: str | None) -> float:
    if expires_at:
        try:
            return datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time() + 3000  # ~50 min conservative default


def _resolve_installation_id(app_jwt: str) -> str | None:
    """Use GH_APP_INSTALLATION_ID, else the sole installation if there's exactly one."""
    explicit = os.environ.get(INSTALLATION_ID_ENV)
    if explicit:
        return explicit
    res = github_api.request("/app/installations?per_page=100", token=app_jwt)
    if isinstance(res, list) and len(res) == 1 and res[0].get("id"):
        return str(res[0]["id"])
    return None


def installation_token() -> str | None:
    """Mint (or return a cached) installation access token.

    Returns None when no App is configured (callers fall back to other credentials).
    Raises GithubAppError when an App *is* configured but unusable."""
    app_id = os.environ.get(APP_ID_ENV)
    key = _private_key()
    if not (app_id and key):
        return None

    cache_key = (app_id, os.environ.get(INSTALLATION_ID_ENV) or "")
    cached = _cache.get(cache_key)
    if cached and cached[1] - _SKEW > time.time():
        return cached[0]

    app_jwt = _build_jwt(app_id, key)
    installation_id = _resolve_installation_id(app_jwt)
    if not installation_id:
        raise GithubAppError(
            f"set {INSTALLATION_ID_ENV} (the App has zero or multiple installations).")

    res = github_api.request(
        f"/app/installations/{installation_id}/access_tokens", method="POST", token=app_jwt)
    if not isinstance(res, dict) or not res.get("token"):
        raise GithubAppError(
            "could not mint an installation token (check the App ID, private key, and installation).")
    token = res["token"]
    _cache[cache_key] = (token, _expiry_epoch(res.get("expires_at")))
    return token
