#!/usr/bin/env python3
"""`saw auth app register` no longer gates on a crypto extra — JWT signing is built in (`lib/jwtsign`),
so registration always proceeds to the manifest flow (no `--force`, no install hint)."""
from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from stayawake.cli.commands import auth
from stayawake.lib import github_app


class TestAppRegisterNoCryptoGate(unittest.TestCase):
    def _args(self, **kw):
        base = {"name": "StayAwakeBot", "no_browser": True}
        base.update(kw)
        return argparse.Namespace(**base)

    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    def test_register_proceeds_and_reports_install(self, reg):
        # Signing is built in, so register never blocks on a missing extra: it drives the manifest flow
        # and, on a completed install, exits 0.
        reg.return_value = {
            "id": "1",
            "slug": "stayawakebot",
            "_installed": True,
            "installation_id": "99",
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args())
        self.assertEqual(rc, 0)
        reg.assert_called_once()
        out = buf.getvalue()
        self.assertIn("registered App", out)
        # No crypto-extra install hint anywhere in the output.
        self.assertNotIn("[app]", out)
        self.assertNotIn("pipx inject", out)

    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    def test_register_reports_incomplete_install(self, reg):
        reg.return_value = {"id": "1", "slug": "stayawakebot", "_installed": False}
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args())
        self.assertEqual(rc, 1)          # install not completed → exit 1, but registration still ran
        reg.assert_called_once()


if __name__ == "__main__":
    unittest.main()
