#!/usr/bin/env python3
"""`saw auth app register` — no crypto gate (signing is built in, `lib/jwtsign`), and it is IDEMPOTENT:
when an App is already configured it does NOT mint a duplicate (GitHub App names are globally unique,
so a fresh manifest run would create a new suffixed App each time). It points the operator at
installing the SAME App on more accounts/orgs, unless `--replace` (or the old App is gone from GitHub)."""
from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from stayawake.cli.commands import auth
from stayawake.lib import github_app


class TestAppRegisterFresh(unittest.TestCase):
    """No local App configured → registration proceeds through the manifest flow."""

    def _args(self, **kw):
        base = {"name": "StayAwakeBot", "no_browser": True, "replace": False, "no_stream": True}
        base.update(kw)
        return argparse.Namespace(**base)

    @mock.patch.object(github_app, "is_configured", return_value=False)
    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    def test_register_proceeds_and_reports_install(self, reg, _cfg):
        reg.return_value = {
            "id": "1", "slug": "stayawakebot", "_installed": True, "installation_id": "99",
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args())
        self.assertEqual(rc, 0)
        reg.assert_called_once()
        out = buf.getvalue()
        self.assertIn("registered App", out)
        self.assertNotIn("[app]", out)          # no crypto-extra hint
        self.assertNotIn("pipx inject", out)

    @mock.patch.object(github_app, "is_configured", return_value=False)
    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    def test_register_reports_incomplete_install(self, reg, _cfg):
        reg.return_value = {"id": "1", "slug": "stayawakebot", "_installed": False}
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args())
        self.assertEqual(rc, 1)                  # install not completed → exit 1, but registration ran
        reg.assert_called_once()


class TestAppRegisterIdempotent(unittest.TestCase):
    """An App is already configured locally → do NOT create a duplicate (the reported bug)."""

    def _args(self, **kw):
        base = {"name": "StayAwakeBot", "no_browser": True, "replace": False, "no_stream": True}
        base.update(kw)
        return argparse.Namespace(**base)

    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch.object(github_app, "load_config",
                       return_value={"app_id": "1", "name": "StayAwakeBot Saw cli",
                                     "slug": "stayawakebot-saw-cli"})
    @mock.patch.object(github_app, "app_exists", return_value=True)
    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    def test_configured_and_exists_refuses_and_guides(self, reg, _exists, _cfg, _isc):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args())
        self.assertEqual(rc, 0)
        reg.assert_not_called()                  # NO duplicate App created
        out = buf.getvalue()
        self.assertIn("already registered", out)
        self.assertIn("apps/stayawakebot-saw-cli/installations/new", out)   # install-more path
        self.assertIn("--replace", out)

    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch.object(github_app, "load_config", return_value={"app_id": "1", "slug": "old"})
    @mock.patch.object(github_app, "app_exists", return_value=False)
    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    def test_configured_but_app_gone_reregisters(self, reg, _exists, _cfg, _isc):
        reg.return_value = {"id": "2", "slug": "new", "_installed": True, "installation_id": "5"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args())
        self.assertEqual(rc, 0)
        reg.assert_called_once()                  # old App is gone → re-register is correct
        self.assertIn("no longer exists", buf.getvalue())

    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch.object(github_app, "load_config", return_value={"app_id": "1", "slug": "x"})
    @mock.patch.object(github_app, "app_exists", return_value=None)
    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    def test_configured_unverifiable_does_not_duplicate(self, reg, _exists, _cfg, _isc):
        # Offline / API unreachable → can't confirm the App is gone → stay cautious, don't duplicate.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args())
        self.assertEqual(rc, 0)
        reg.assert_not_called()
        self.assertIn("couldn't confirm", buf.getvalue())

    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch.object(github_app, "load_config", return_value={"app_id": "1", "slug": "x"})
    @mock.patch.object(github_app, "app_exists", return_value=True)
    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    def test_replace_forces_new_registration(self, reg, _exists, _cfg, _isc):
        reg.return_value = {"id": "9", "slug": "brand-new", "_installed": True, "installation_id": "7"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args(replace=True))
        self.assertEqual(rc, 0)
        reg.assert_called_once()                  # --replace bypasses the idempotency guard
        _exists.assert_not_called()               # and doesn't even probe (we're forcing a new App)


if __name__ == "__main__":
    unittest.main()
