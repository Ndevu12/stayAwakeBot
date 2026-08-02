#!/usr/bin/env python3
"""StayAwakeBot GitHub App manifest + local register/install flow (Phase 1).

Registers an *operator-managed* App from a pre-filled manifest (GitHub's App-manifest
handshake), then continues through installation via `setup_url` so the loopback captures
`installation_id` without a manual URL copy step. The operator owns App ID + PEM — we
never ship a shared private key.
"""
from __future__ import annotations

import json
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from stayawake.lib import github_app

# Permissions required for scan / fix PR / guard workflow PR / optional issue alerts.
DEFAULT_PERMISSIONS = {
    "metadata": "read",
    "contents": "write",
    "pull_requests": "write",
    "workflows": "write",
    "issues": "write",
}

_MANIFEST_NAME = "StayAwakeBot"
_MANIFEST_URL = "https://github.com/Ndevu12/stayAwakeBot"
_MANIFEST_DESCRIPTION = (
    "Operator-managed GitHub App for the StayAwakeBot (`saw`) CLI — "
    "detect, report, and remediate supply-chain worms on the repos you choose. "
    "Credentials stay on your machine; you own the App registration."
)


def app_icon_path() -> Path | None:
    """Packaged StayAwakeBot App icon (PNG), or None if the asset is missing."""
    path = Path(__file__).resolve().parent / "data" / "stayawakebot-app-icon.png"
    return path if path.is_file() else None


def _state_matches(got: str | None, nonce: str) -> bool:
    """True iff `got` (a request's `state` query value) equals the run's `nonce` (#1292). Fails CLOSED
    on a missing/empty value, and uses a constant-time compare so a near-miss leaks no timing signal."""
    return bool(got) and secrets.compare_digest(got, nonce)


def build_manifest(*, redirect_url: str, setup_url: str,
                    name: str = _MANIFEST_NAME) -> dict[str, Any]:
    """Manifest body for POST to GitHub's new-app form. No webhook/events (API-only App)."""
    return {
        "name": name,
        "url": _MANIFEST_URL,
        "description": _MANIFEST_DESCRIPTION,
        "redirect_url": redirect_url,
        "callback_urls": [redirect_url],
        "setup_url": setup_url,
        # "Any account" — REQUIRED so the operator can install the App on their organizations, not
        # just their personal account. GitHub's manifest `public` is binary: false = "Only on this
        # account" (installable ONLY on the owner's personal account, so the install page skips the
        # account picker and orgs are unreachable); true = "Any account" (the picker lists the personal
        # account + every org the operator administers). Trade-off (accepted): a public App has a public
        # install page (github.com/apps/<slug>) and CAN be installed by anyone who finds the slug — and
        # since the operator holds the key and the App requests contents/PR/workflows write, a stranger
        # who installs it grants the KEY-HOLDER token-mintable write to THEIR repos (their choice, not a
        # leak of the operator's key or repos). The slug is unlisted (not Marketplace); this is the
        # unblock for multi-account scanning and the operator owns their App + key.
        "public": True,
        "default_permissions": dict(DEFAULT_PERMISSIONS),
        "default_events": [],
    }


def exchange_manifest_code(code: str) -> dict:
    """POST /app-manifests/{code}/conversions → App id, pem, slug, …"""
    url = f"https://api.github.com/app-manifests/{urllib.parse.quote(code)}/conversions"
    req = urllib.request.Request(
        url, data=b"{}", method="POST",
        headers={"Accept": "application/vnd.github+json",
                 "Content-Type": "application/json",
                 "User-Agent": "StayAwakeBot/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as he:
        detail = he.read().decode() if hasattr(he, "read") else str(he)
        raise github_app.GithubAppError(
            f"manifest conversion failed ({he.code}): {detail}") from he


def register_via_browser(*, name: str = _MANIFEST_NAME, open_browser: bool = True,
                         timeout_s: float = 300.0,
                         install_timeout_s: float = 600.0) -> dict:
    """Drive App create + install on one loopback HTTP server.

    1. POST pre-filled manifest to GitHub (create App).
    2. Exchange conversion code → save PEM/app_id locally.
    3. Open the install page; GitHub redirects to `setup_url` with `installation_id`.
    4. Persist `installation_id` and return the conversion payload (+ installation_id).

    If install is skipped/timed out, credentials are still saved and the install URL is
    included on the returned dict as `_install_url` for the CLI to print.
    """
    state: dict[str, Any] = {
        "code": None, "error": None,
        "installation_id": None, "setup_error": None,
    }
    # Anti-CSRF nonce bound to THIS run (#1292). It rides GitHub's own `state` param: baked into the
    # new-app form action (echoed back to /callback) and into setup_url (returned to /setup). A forged
    # local request to the ephemeral loopback port can't know it, so /callback and /setup reject any
    # request whose `state` doesn't match. Constant-time compared to avoid a timing oracle.
    nonce = secrets.token_urlsafe(32)
    registered = threading.Event()
    installed = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: ARG002 — keep loopback quiet
            return

        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            port = self.server.server_port
            if parsed.path in ("/", "/start"):
                nonce_q = urllib.parse.quote(nonce)
                manifest = build_manifest(
                    redirect_url=f"http://127.0.0.1:{port}/callback",
                    # state on setup_url so the install redirect (/setup) is CSRF-checked too.
                    setup_url=f"http://127.0.0.1:{port}/setup?state={nonce_q}",
                    name=name,
                )
                # state on the new-app form action → GitHub echoes it to /callback with the code.
                new_app_url = f"https://github.com/settings/apps/new?state={nonce_q}"
                body = _start_page(manifest, new_app_url=new_app_url).encode("utf-8")
                self._ok(body)
                return
            if parsed.path == "/callback":
                qs = urllib.parse.parse_qs(parsed.query)
                if not self._state_ok(qs):
                    state["error"] = "state mismatch — possible CSRF; the callback was ignored"
                    self._fail(_html("Registration rejected",
                                     "Anti-CSRF state check failed — return to the terminal."))
                    registered.set()
                    return
                if qs.get("code"):
                    state["code"] = qs["code"][0]
                    msg = _html(
                        "StayAwakeBot App registered",
                        "Next: GitHub will open the <strong>install</strong> page. "
                        "Pick the account/repos, then you will return here automatically.",
                    )
                    self._ok(msg)
                else:
                    state["error"] = qs.get("error_description", qs.get("error", ["unknown"]))[0]
                    self._fail(_html("Registration failed",
                                     "Return to the terminal for details."))
                registered.set()
                return
            if parsed.path == "/setup":
                qs = urllib.parse.parse_qs(parsed.query)
                if not self._state_ok(qs):
                    state["setup_error"] = "state mismatch — possible CSRF; the install callback was ignored"
                    self._fail(_html("Install rejected",
                                     "Anti-CSRF state check failed — return to the terminal."))
                    installed.set()
                    return
                iid = (qs.get("installation_id") or [None])[0]
                if iid:
                    state["installation_id"] = str(iid)
                    msg = _html(
                        "StayAwakeBot App installed",
                        "You can close this tab and return to the terminal.",
                    )
                    self._ok(msg)
                else:
                    state["setup_error"] = qs.get("error_description",
                                                 qs.get("error", ["missing installation_id"]))[0]
                    self._fail(_html("Install callback incomplete",
                                     "Return to the terminal for details."))
                installed.set()
                return
            self.send_response(404)
            self.end_headers()

        def _state_ok(self, qs: dict) -> bool:
            """True iff the request carries the run's anti-CSRF `state` nonce (#1292)."""
            return _state_matches((qs.get("state") or [None])[0], nonce)

        def _ok(self, body: bytes) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _fail(self, body: bytes) -> None:
            self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    start_url = f"http://127.0.0.1:{port}/start"
    try:
        if open_browser:
            webbrowser.open(start_url)
        if not registered.wait(timeout_s):
            raise github_app.GithubAppError(
                f"timed out waiting for GitHub redirect (open {start_url} manually and retry)")
        if state["error"]:
            raise github_app.GithubAppError(f"GitHub returned an error: {state['error']}")
        if not state["code"]:
            raise github_app.GithubAppError("no conversion code received from GitHub")

        payload = exchange_manifest_code(state["code"])
        pem = payload.get("pem")
        app_id = payload.get("id")
        if not pem or not app_id:
            raise github_app.GithubAppError("conversion response missing id/pem")
        slug = payload.get("slug")
        display = payload.get("name") or name
        github_app.save_config(str(app_id), pem, slug=slug, name=display)

        install = install_url(slug)
        payload["_install_url"] = install
        payload["_settings_url"] = settings_url(slug, app_id=app_id)
        payload["_icon_path"] = str(app_icon_path()) if app_icon_path() else None

        if open_browser:
            webbrowser.open(install)
        if installed.wait(timeout=install_timeout_s):
            if state["setup_error"]:
                raise github_app.GithubAppError(
                    f"install callback error: {state['setup_error']}")
            iid = state["installation_id"]
            if iid:
                github_app.save_config(str(app_id), pem, installation_id=iid,
                                      slug=slug, name=display)
                payload["installation_id"] = iid
                payload["_installed"] = True
            else:
                payload["_installed"] = False
        else:
            payload["_installed"] = False
        return payload
    finally:
        server.shutdown()
        server.server_close()      # release the listening socket (not just stop serve_forever)


def _html(title: str, body: str) -> bytes:
    return (f"<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
            f"<title>{title}</title></head><body>"
            f"<h2>{title}</h2><p>{body}</p></body></html>").encode("utf-8")


def _start_page(manifest: dict, *,
                new_app_url: str = "https://github.com/settings/apps/new") -> str:
    """Auto-submitting HTML form that posts the manifest to GitHub's new-app endpoint. `new_app_url`
    carries the per-run `?state=` nonce (#1292) so GitHub echoes it back to /callback for CSRF
    verification; it is HTML-escaped into the form action like the manifest body."""
    manifest_json = json.dumps(manifest)
    def _esc(s: str) -> str:
        return (s.replace("&", "&amp;").replace('"', "&quot;")
                 .replace("<", "&lt;").replace(">", "&gt;"))
    escaped = _esc(manifest_json)
    action = _esc(new_app_url)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Register StayAwakeBot</title></head>
<body>
  <p>Continuing to GitHub to create your StayAwakeBot App…</p>
  <form id="f" action="{action}" method="post">
    <input type="hidden" name="manifest" value="{escaped}">
    <button type="submit">Create GitHub App</button>
  </form>
  <script>document.getElementById("f").submit();</script>
</body></html>
"""


def install_url(slug: str | None) -> str:
    """Where the operator installs the newly registered App on an account/org."""
    if slug:
        return f"https://github.com/apps/{slug}/installations/new"
    return "https://github.com/settings/apps"


def settings_url(slug: str | None, *, app_id: int | str | None = None) -> str:
    """GitHub App settings (Display information — upload the StayAwakeBot icon here)."""
    if slug:
        return f"https://github.com/settings/apps/{slug}"
    if app_id:
        return f"https://github.com/settings/apps/{app_id}"
    return "https://github.com/settings/apps"
