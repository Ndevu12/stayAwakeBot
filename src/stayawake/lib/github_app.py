#!/usr/bin/env python3
"""GitHub App authentication — mint short-lived installation tokens.

Optional feature: needs `pip install "stayawakebot[app]"` (PyJWT[crypto]). A GitHub App is
the production way to scan/remediate/guard org-wide: an admin installs it once on selected
repos and it mints **1-hour, auto-rotating installation tokens** scoped to exactly the
granted permissions — no human PAT to leak, fully revocable, and the install itself
defines scope.

Security: JWT signing is delegated to the audited PyJWT/cryptography stack. Tokens/keys are
returned to callers but never logged here. Credentials may come from env OR from the local
config written by `saw auth app register` (`~/.config/saw/github-app.json`).

Configuration (env wins over the config file):
  GH_APP_ID                 numeric App ID (not secret)
  GH_APP_PRIVATE_KEY        PEM contents of the App private key (secret), OR
  GH_APP_PRIVATE_KEY_PATH   path to the .pem
  GH_APP_INSTALLATION_ID    optional; if omitted and the App has exactly one
                            installation, that one is used

Phase 1 registers an operator-managed App via `saw auth app register` (you own App ID + PEM).
"""
from __future__ import annotations

import json
import os
import stat
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
# cache_key -> (token, expires_epoch, permissions_dict)
_cache: dict[tuple[str, str], tuple[str, float, dict]] = {}
# token -> permissions (so AuthZ can introspect the live installation token)
_token_perms: dict[str, dict[str, str]] = {}


class GithubAppError(RuntimeError):
    """App auth is configured but cannot be completed (missing extra, bad key, no
    resolvable installation, API failure)."""


def _xdg_config_home() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return Path(xdg) if xdg else Path.home() / ".config"


def config_path() -> Path:
    """XDG path for App credentials — under `saw/` to match `~/.cache/saw/`."""
    return _xdg_config_home() / "saw" / "github-app.json"


def legacy_config_path() -> Path:
    """Pre-rename path (`~/.config/stayawake/…`); migrated on read when present."""
    return _xdg_config_home() / "stayawake" / "github-app.json"


def _read_config_file(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data.get("app_id") or not data.get("private_key_pem"):
        return None
    return data


def _migrate_legacy_config() -> Path | None:
    """Move `~/.config/stayawake/github-app.json` → `~/.config/saw/` once, if needed."""
    dest = config_path()
    if dest.is_file():
        return None
    src = legacy_config_path()
    if not src.is_file():
        return None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
        try:
            dest.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        try:
            src.unlink()
        except OSError:
            pass
        return dest
    except OSError:
        return None


def load_config() -> dict | None:
    """Local App credentials from `saw auth app register`, or None."""
    _migrate_legacy_config()
    return _read_config_file(config_path())


def save_config(app_id: str, private_key_pem: str, *, installation_id: str | None = None,
                slug: str | None = None, name: str | None = None) -> Path:
    """Persist App credentials from the manifest flow. Mode 0600 on the file."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "app_id": str(app_id),
        "private_key_pem": private_key_pem,
        "installation_id": installation_id,
        "slug": slug,
        "name": name,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass
    # Drop a leftover legacy file so the two never diverge.
    legacy = legacy_config_path()
    if legacy.is_file() and legacy.resolve() != path.resolve():
        try:
            legacy.unlink()
        except OSError:
            pass
    _cache.clear()
    _token_perms.clear()
    return path


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
    cfg = load_config()
    if cfg and cfg.get("private_key_pem"):
        return cfg["private_key_pem"]
    return None


def _app_id() -> str | None:
    return os.environ.get(APP_ID_ENV) or ((load_config() or {}).get("app_id"))


def is_configured() -> bool:
    """True if a GitHub App is configured (env or `saw auth app register` config)."""
    return bool(_app_id() and _private_key())


def jwt_available() -> bool:
    """True when the optional PyJWT[crypto] extra can be imported."""
    try:
        import jwt  # noqa: F401
        return True
    except ImportError:
        return False


APP_EXTRA_HINT = 'pip install "stayawakebot[app]"'


def installation_actor_label() -> str | None:
    """Short label for Session.actor when using an App credential."""
    cfg = load_config() or {}
    iid = os.environ.get(INSTALLATION_ID_ENV) or cfg.get("installation_id")
    slug = cfg.get("slug") or cfg.get("name")
    if iid:
        return f"installation:{iid}" + (f" ({slug})" if slug else "")
    if slug:
        return f"app:{slug}"
    aid = _app_id()
    return f"app:{aid}" if aid else "github-app"


def cached_permissions_for_token(token: str) -> dict[str, str] | None:
    """Permissions recorded when this installation token was minted, if still cached."""
    return _token_perms.get(token)


def _build_jwt(app_id: str, private_key: str) -> str:
    """Sign the App JWT (RS256). Requires the optional PyJWT[crypto] extra."""
    try:
        import jwt  # PyJWT — only needed for App auth (optional [app] extra)
    except ImportError as e:
        raise GithubAppError(
            f"GitHub App auth needs PyJWT — install the extra: {APP_EXTRA_HINT}."
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
    """Env / config installation id, else the sole installation if there's exactly one."""
    explicit = os.environ.get(INSTALLATION_ID_ENV) or (load_config() or {}).get("installation_id")
    if explicit:
        return str(explicit)
    res = github_api.request("/app/installations?per_page=100", token=app_jwt)
    if isinstance(res, list) and len(res) == 1 and res[0].get("id"):
        return str(res[0]["id"])
    return None


def installation_token() -> str | None:
    """Mint (or return a cached) installation access token.

    Returns None when no App is configured (callers fall back to other credentials).
    Raises GithubAppError when an App *is* configured but unusable."""
    app_id = _app_id()
    key = _private_key()
    if not (app_id and key):
        return None

    inst_env = os.environ.get(INSTALLATION_ID_ENV) or (load_config() or {}).get("installation_id") or ""
    cache_key = (str(app_id), str(inst_env))
    cached = _cache.get(cache_key)
    if cached and cached[1] - _SKEW > time.time():
        return cached[0]

    app_jwt = _build_jwt(str(app_id), key)
    installation_id = _resolve_installation_id(app_jwt)
    if not installation_id:
        raise GithubAppError(
            f"set {INSTALLATION_ID_ENV} (or re-run `saw auth app register` after installing the App "
            "on an account/org — zero or multiple installations found).")

    res = github_api.request(
        f"/app/installations/{installation_id}/access_tokens", method="POST", token=app_jwt)
    if not isinstance(res, dict) or not res.get("token"):
        raise GithubAppError(
            "could not mint an installation token (check the App ID, private key, and installation).")
    token = res["token"]
    perms = res.get("permissions") if isinstance(res.get("permissions"), dict) else {}
    _cache[cache_key] = (token, _expiry_epoch(res.get("expires_at")), perms)
    if perms:
        _token_perms[token] = {str(k): str(v) for k, v in perms.items()}
    return token
