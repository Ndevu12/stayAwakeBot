#!/usr/bin/env python3
"""StayAwake Saw GitHub App manifest + local register flow (Phase 1).

Registers a *self-owned* App from a pre-filled manifest (GitHub's App-manifest handshake).
The operator owns App ID + PEM — we never ship a shared private key. Official public App
(Phase 2) is deferred: GitHub issue #1277.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
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

_MANIFEST_NAME = "StayAwake Saw"
_MANIFEST_URL = "https://github.com/Ndevu12/stayAwakeBot"


def build_manifest(*, redirect_url: str, name: str = _MANIFEST_NAME) -> dict[str, Any]:
    """Manifest body for POST to GitHub's new-app form. No webhook/events (API-only App)."""
    return {
        "name": name,
        "url": _MANIFEST_URL,
        "redirect_url": redirect_url,
        "callback_urls": [redirect_url],
        "public": False,
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
                         timeout_s: float = 300.0) -> dict:
    """Drive the GitHub App-manifest flow on a loopback HTTP server.

    Returns the conversion payload (includes id, pem, slug). Saves credentials via
    `github_app.save_config`. Raises GithubAppError on failure / timeout.
    """
    result: dict[str, Any] = {"code": None, "error": None}
    ready = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # noqa: ARG002 — keep loopback quiet
            return

        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path in ("/", "/start"):
                manifest = build_manifest(redirect_url=f"http://127.0.0.1:{self.server.server_port}/callback",
                                          name=name)
                body = _start_page(manifest).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/callback":
                qs = urllib.parse.parse_qs(parsed.query)
                if qs.get("code"):
                    result["code"] = qs["code"][0]
                    msg = b"<html><body><h2>StayAwake Saw App registered.</h2>" \
                          b"<p>You can close this tab and return to the terminal.</p></body></html>"
                    self.send_response(200)
                else:
                    result["error"] = qs.get("error_description", qs.get("error", ["unknown"]))[0]
                    msg = b"<html><body><h2>Registration failed.</h2>" \
                          b"<p>Return to the terminal for details.</p></body></html>"
                    self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
                ready.set()
                return
            self.send_response(404)
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    start_url = f"http://127.0.0.1:{port}/start"
    try:
        if open_browser:
            webbrowser.open(start_url)
        if not ready.wait(timeout_s):
            raise github_app.GithubAppError(
                f"timed out waiting for GitHub redirect (open {start_url} manually and retry)")
        if result["error"]:
            raise github_app.GithubAppError(f"GitHub returned an error: {result['error']}")
        if not result["code"]:
            raise github_app.GithubAppError("no conversion code received from GitHub")
        payload = exchange_manifest_code(result["code"])
        pem = payload.get("pem")
        app_id = payload.get("id")
        if not pem or not app_id:
            raise github_app.GithubAppError("conversion response missing id/pem")
        github_app.save_config(
            str(app_id), pem,
            slug=payload.get("slug"),
            name=payload.get("name") or name,
        )
        return payload
    finally:
        server.shutdown()


def _start_page(manifest: dict) -> str:
    """Auto-submitting HTML form that posts the manifest to GitHub's new-app endpoint."""
    manifest_json = json.dumps(manifest)
    # Escape for HTML attribute context
    escaped = (manifest_json.replace("&", "&amp;").replace('"', "&quot;")
               .replace("<", "&lt;").replace(">", "&gt;"))
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Register StayAwake Saw</title></head>
<body>
  <p>Continuing to GitHub to create your StayAwake Saw App…</p>
  <form id="f" action="https://github.com/settings/apps/new" method="post">
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
