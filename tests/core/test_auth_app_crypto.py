#!/usr/bin/env python3
"""App crypto install hints + `saw auth app register` gate."""
from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from importlib.metadata import PackageNotFoundError
from unittest import mock

from stayawake.cli.commands import auth
from stayawake.lib import github_app


class TestAppCryptoInstallHint(unittest.TestCase):
    @mock.patch.object(github_app, "_running_under_pipx", return_value=False)
    @mock.patch.object(github_app, "_package_project_root", return_value=None)
    @mock.patch("stayawake.lib.github_app.distribution")
    def test_pip_install_when_wheel(self, dist_fn, _root, _pipx):
        dist_fn.return_value = mock.Mock()
        with mock.patch.object(github_app, "_distribution_is_editable", return_value=False):
            self.assertEqual(github_app.app_crypto_install_hint(), github_app.APP_EXTRA_HINT)
            self.assertIn("stayawakebot[app]", github_app.app_crypto_install_hint())

    @mock.patch.object(github_app, "_running_under_pipx", return_value=False)
    @mock.patch.object(github_app, "_package_project_root", return_value="/tmp/stayAwakeBot")
    @mock.patch("stayawake.lib.github_app.distribution")
    def test_editable_hint(self, dist_fn, _root, _pipx):
        dist_fn.return_value = mock.Mock()
        with mock.patch.object(github_app, "_distribution_is_editable", return_value=True):
            self.assertIn('-e ".[app]"', github_app.app_crypto_install_hint())

    @mock.patch("stayawake.lib.github_app.distribution", side_effect=PackageNotFoundError("x"))
    @mock.patch.object(github_app, "_package_project_root")
    def test_source_tree_hint(self, root, _dist):
        root.return_value = mock.Mock()
        self.assertIn('-e ".[app]"', github_app.app_crypto_install_hint())

    @mock.patch.object(github_app, "_running_under_pipx", return_value=True)
    @mock.patch.object(github_app, "_package_project_root", return_value=None)
    @mock.patch("stayawake.lib.github_app.distribution")
    def test_pipx_hint(self, dist_fn, _root, _pipx):
        dist_fn.return_value = mock.Mock()
        with mock.patch.object(github_app, "_distribution_is_editable", return_value=False):
            hint = github_app.app_crypto_install_hint()
            self.assertIn("pipx inject", hint)
            self.assertIn("pyjwt", hint)


class TestAppRegisterGate(unittest.TestCase):
    def _args(self, **kw):
        base = {"name": "StayAwakeBot", "no_browser": True, "force": False}
        base.update(kw)
        return argparse.Namespace(**base)

    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    @mock.patch.object(github_app, "jwt_available", return_value=False)
    def test_register_blocks_without_jwt(self, _jwt, reg):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args())
        self.assertEqual(rc, 2)
        reg.assert_not_called()
        out = buf.getvalue()
        self.assertTrue('-e ".[app]"' in out or "stayawakebot[app]" in out)

    @mock.patch("stayawake.lib.github_app_manifest.register_via_browser")
    @mock.patch.object(github_app, "jwt_available", return_value=False)
    def test_register_force_proceeds(self, _jwt, reg):
        reg.return_value = {
            "id": "1",
            "slug": "stayawakebot",
            "_installed": True,
            "installation_id": "99",
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = auth._app_register(self._args(force=True))
        self.assertEqual(rc, 0)
        reg.assert_called_once()
        self.assertIn("continuing without PyJWT", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
