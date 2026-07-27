#!/usr/bin/env python3
"""`saw doctor` App crypto readiness (mirrors auth status)."""
from __future__ import annotations

import argparse
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from stayawake.cli.commands import doctor
from stayawake.core.identity import Capability, Session
from stayawake.core.identity.outcomes import Decision
from stayawake.lib import github_app


def _sess_with_token() -> Session:
    return Session(
        token="tok",
        source="gh",
        kind="user",
        actor="alice",
        live=True,
        scopes=frozenset({"repo", "workflow"}),
        capabilities=frozenset({
            Capability.CONTENTS_WRITE,
            Capability.PULL_REQUESTS_WRITE,
            Capability.WORKFLOWS_WRITE,
        }),
    )


def _allow(intent, **kw):
    return Decision(allowed=True, intent=intent)


class TestDoctorAppCrypto(unittest.TestCase):
    def _run(self, *, json_out: bool = False) -> tuple[int, str]:
        args = argparse.Namespace(json=json_out, quiet=False)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = doctor.run(args)
        return rc, buf.getvalue()

    @mock.patch.object(github_app, "config_path", return_value="/tmp/saw/github-app.json")
    @mock.patch.object(
        github_app,
        "app_crypto_install_hint",
        return_value='pip install "stayawakebot[app]"',
    )
    @mock.patch.object(github_app, "load_config", return_value={"app_id": "1"})
    @mock.patch.object(github_app, "jwt_available", return_value=False)
    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch("stayawake.cli.commands.doctor.require", side_effect=_allow)
    @mock.patch("stayawake.cli.commands.doctor.resolve_session", return_value=_sess_with_token())
    def test_human_app_saved_without_pyjwt(self, *_mocks):
        rc, out = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("App saved but not usable yet", out)
        self.assertNotIn("Saw App config present", out)
        self.assertIn("stayawakebot[app]", out)

    @mock.patch.object(
        github_app,
        "app_crypto_install_hint",
        return_value='pip install "stayawakebot[app]"',
    )
    @mock.patch.object(github_app, "load_config", return_value={})
    @mock.patch.object(github_app, "jwt_available", return_value=False)
    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch("stayawake.cli.commands.doctor.require", side_effect=_allow)
    @mock.patch("stayawake.cli.commands.doctor.resolve_session", return_value=_sess_with_token())
    def test_human_app_env_only_without_pyjwt(self, *_mocks):
        rc, out = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("App configured but not usable yet", out)
        self.assertNotIn("App saved but not usable yet", out)

    @mock.patch.object(github_app, "config_path", return_value="/tmp/saw/github-app.json")
    @mock.patch.object(github_app, "jwt_available", return_value=True)
    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch("stayawake.cli.commands.doctor.require", side_effect=_allow)
    @mock.patch("stayawake.cli.commands.doctor.resolve_session", return_value=_sess_with_token())
    def test_human_app_ready(self, *_mocks):
        rc, out = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("✓ Saw App config present", out)

    @mock.patch.object(github_app, "jwt_available", return_value=False)
    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch("stayawake.cli.commands.doctor.require", side_effect=_allow)
    @mock.patch("stayawake.cli.commands.doctor.resolve_session", return_value=_sess_with_token())
    def test_json_app_jwt_available_false(self, *_mocks):
        rc, out = self._run(json_out=True)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertTrue(data["app_configured"])
        self.assertFalse(data["app_jwt_available"])


if __name__ == "__main__":
    unittest.main()
