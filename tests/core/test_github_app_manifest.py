#!/usr/bin/env python3
"""StayAwakeBot App manifest branding + install URL helpers + loopback CSRF (state nonce)."""
from __future__ import annotations

import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import unittest
from unittest import mock

from stayawake.lib import github_app_manifest as manifest


class TestManifestBranding(unittest.TestCase):
    def test_default_name_is_stayawakebot(self):
        m = manifest.build_manifest(
            redirect_url="http://127.0.0.1:9/callback",
            setup_url="http://127.0.0.1:9/setup",
        )
        self.assertEqual(m["name"], "StayAwakeBot")
        self.assertIn("setup_url", m)
        self.assertEqual(m["setup_url"], "http://127.0.0.1:9/setup")
        self.assertIn("operator-managed", m["description"].lower())
        self.assertNotIn("deferred", m["description"].lower())
        self.assertNotIn("1277", m["description"])

    def test_icon_ships_with_package(self):
        path = manifest.app_icon_path()
        self.assertIsNotNone(path)
        self.assertTrue(path.is_file())
        self.assertGreater(path.stat().st_size, 1000)

    def test_install_and_settings_urls(self):
        self.assertEqual(manifest.install_url("stayawakebot"),
                         "https://github.com/apps/stayawakebot/installations/new")
        self.assertEqual(manifest.settings_url("stayawakebot"),
                         "https://github.com/settings/apps/stayawakebot")


class TestAppExtraHint(unittest.TestCase):
    def test_hint_uses_distribution_name(self):
        from stayawake.lib import github_app
        self.assertIn("stayawakebot[app]", github_app.APP_EXTRA_HINT)
        self.assertNotIn("stayawake[app]", github_app.APP_EXTRA_HINT)


class TestStateNonce(unittest.TestCase):
    """The anti-CSRF `state` primitive (#1292): constant-time, fail-closed."""

    def test_matches_correct(self):
        self.assertTrue(manifest._state_matches("abc123", "abc123"))

    def test_rejects_wrong(self):
        self.assertFalse(manifest._state_matches("abc123", "xyz789"))

    def test_rejects_missing_or_empty(self):
        self.assertFalse(manifest._state_matches(None, "abc123"))
        self.assertFalse(manifest._state_matches("", "abc123"))

    def test_start_page_threads_escaped_state_into_form_action(self):
        page = manifest._start_page(
            manifest.build_manifest(redirect_url="http://127.0.0.1:9/callback",
                                    setup_url="http://127.0.0.1:9/setup?state=N0NCE"),
            new_app_url="https://github.com/settings/apps/new?state=N0NCE&x=<b>")
        action = re.search(r'action="([^"]*)"', page).group(1)
        self.assertIn("state=N0NCE", action)          # nonce carried on the new-app POST
        self.assertIn("&amp;", action)                # HTML-escaped (& → &amp;)
        self.assertIn("&lt;b&gt;", action)            # ...and < > too


class TestLoopbackCsrf(unittest.TestCase):
    """End-to-end: the loopback /callback and /setup handlers must reject a request whose `state`
    doesn't match the run's nonce, and accept the valid flow. Drives the REAL server that
    `register_via_browser` starts; the port is learned from the captured `webbrowser.open` URL and
    the nonce is read back from the auto-submit page's form action. Network + persistence mocked."""

    @staticmethod
    def _get(url):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode()
            finally:
                e.close()

    @staticmethod
    def _wait(pred, timeout=8.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            v = pred()
            if v:
                return v
            time.sleep(0.02)
        return None

    def _launch(self, opened):
        result = {}

        def run():
            try:
                result["ok"] = manifest.register_via_browser(timeout_s=8, install_timeout_s=8)
            except Exception as e:  # noqa: BLE001 — capture for the assertion
                result["err"] = e
        t = threading.Thread(target=run, daemon=True)
        t.start()
        start_url = self._wait(lambda: next((u for u in opened if "/start" in u), None))
        self.assertIsNotNone(start_url, "server never advertised its /start URL")
        port = urllib.parse.urlparse(start_url).port
        _, page = self._get(f"http://127.0.0.1:{port}/start")
        nonce = re.search(r"[?&]state=([A-Za-z0-9_\-]+)", page).group(1)
        return t, result, port, nonce

    def test_forged_callback_wrong_state_is_rejected(self):
        opened = []
        with mock.patch.object(manifest.webbrowser, "open", side_effect=lambda u: opened.append(u)), \
             mock.patch.object(manifest, "exchange_manifest_code") as exch:
            t, result, port, _nonce = self._launch(opened)
            # a forged callback that does NOT know the nonce, carrying an attacker code
            code, _ = self._get(f"http://127.0.0.1:{port}/callback?state=WRONG&code=evil")
            self.assertEqual(code, 400)               # handler rejects with 400
            t.join(timeout=8)
        # the run aborts with a state-mismatch error, and the attacker's code is NEVER exchanged
        self.assertIsInstance(result.get("err"), manifest.github_app.GithubAppError)
        self.assertIn("state mismatch", str(result["err"]).lower())
        exch.assert_not_called()

    def test_valid_flow_with_correct_state_completes(self):
        opened = []
        payload = {"id": 123, "pem": "KEY", "slug": "stayawakebot", "name": "StayAwakeBot"}
        with mock.patch.object(manifest.webbrowser, "open", side_effect=lambda u: opened.append(u)), \
             mock.patch.object(manifest, "exchange_manifest_code", return_value=payload) as exch, \
             mock.patch.object(manifest.github_app, "save_config"):
            t, result, port, nonce = self._launch(opened)
            c1, _ = self._get(f"http://127.0.0.1:{port}/callback?state={nonce}&code=good")
            self.assertEqual(c1, 200)
            c2, _ = self._get(f"http://127.0.0.1:{port}/setup?state={nonce}&installation_id=42")
            self.assertEqual(c2, 200)
            t.join(timeout=8)
        self.assertIsNone(result.get("err"), f"unexpected error: {result.get('err')}")
        exch.assert_called_once_with("good")          # the VALID code was exchanged (not 'evil')
        self.assertEqual(result["ok"].get("installation_id"), "42")


if __name__ == "__main__":
    unittest.main()
