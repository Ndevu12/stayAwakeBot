#!/usr/bin/env python3
"""`saw doctor` App readiness — signing is built in (`lib/jwtsign`), so a configured App reports
present with no crypto-extra caveat and no `app_jwt_available` field."""
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
    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch("stayawake.cli.commands.doctor.require", side_effect=_allow)
    @mock.patch("stayawake.cli.commands.doctor.resolve_session", return_value=_sess_with_token())
    def test_human_app_present_no_crypto_caveat(self, *_mocks):
        rc, out = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("✓ Saw App config present", out)
        self.assertNotIn("not usable yet", out)
        self.assertNotIn("[app]", out)

    @mock.patch.object(github_app, "is_configured", return_value=True)
    @mock.patch("stayawake.cli.commands.doctor.require", side_effect=_allow)
    @mock.patch("stayawake.cli.commands.doctor.resolve_session", return_value=_sess_with_token())
    def test_json_has_no_jwt_available_field(self, *_mocks):
        rc, out = self._run(json_out=True)
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertTrue(data["app_configured"])
        self.assertNotIn("app_jwt_available", data)


if __name__ == "__main__":
    unittest.main()
