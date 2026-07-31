#!/usr/bin/env python3
"""GitHub App auth: installation-token minting, caching, graceful degradation.

These tests don't require the optional PyJWT[crypto] extra — the JWT signing seam is
mocked, and the missing-extra path is exercised by forcing the `import jwt` to fail.
"""
from __future__ import annotations

import builtins
import json
import os
import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest import mock

from stayawake.lib import github_app, auth

_FUTURE = "2099-01-01T00:00:00Z"   # far-future expiry → cache stays valid in-test
_APP_ENV = {"GH_APP_ID": "123", "GH_APP_PRIVATE_KEY": "-----PEM-----",
            "GH_APP_INSTALLATION_ID": "42"}


class TestConfig(unittest.TestCase):
    def test_not_configured_returns_none(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(github_app, "load_config", return_value=None):
            self.assertIsNone(github_app.installation_token())
            self.assertFalse(github_app.is_configured())

    def test_is_configured_with_app_env(self):
        with mock.patch.dict(os.environ, _APP_ENV, clear=True), \
             mock.patch.object(github_app, "load_config", return_value=None):
            self.assertTrue(github_app.is_configured())

    def test_private_key_from_path(self):
        with NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write("-----FROM FILE-----")
            path = f.name
        try:
            with mock.patch.dict(os.environ, {"GH_APP_ID": "1", "GH_APP_PRIVATE_KEY_PATH": path},
                                 clear=True), \
                 mock.patch.object(github_app, "load_config", return_value=None):
                self.assertEqual(github_app._private_key(), "-----FROM FILE-----")
                self.assertTrue(github_app.is_configured())
        finally:
            os.unlink(path)


class TestMinting(unittest.TestCase):
    def setUp(self):
        github_app._cache.clear()
        github_app._token_perms.clear()
        self._cfg = mock.patch.object(github_app, "load_config", return_value=None)
        self._cfg.start()

    def tearDown(self):
        self._cfg.stop()

    def test_mints_token_with_explicit_installation(self):
        with mock.patch.dict(os.environ, _APP_ENV, clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request",
                               return_value={"token": "ghs_inst", "expires_at": _FUTURE}) as req:
            self.assertEqual(github_app.installation_token(), "ghs_inst")
        # explicit installation id ⇒ only the access_tokens POST, no discovery call
        req.assert_called_once()
        self.assertIn("/app/installations/42/access_tokens", req.call_args.args[0])

    def test_caches_token(self):
        with mock.patch.dict(os.environ, _APP_ENV, clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request",
                               return_value={"token": "ghs_inst", "expires_at": _FUTURE}) as req:
            github_app.installation_token()
            github_app.installation_token()        # second call should be cached
        req.assert_called_once()

    def test_resolves_single_installation(self):
        env = {k: v for k, v in _APP_ENV.items() if k != "GH_APP_INSTALLATION_ID"}
        calls = {"n": 0}

        def fake_request(path, method="GET", token=None, data=None):
            calls["n"] += 1
            if path.startswith("/app/installations?"):
                return [{"id": 7}]                  # exactly one installation
            return {"token": "ghs_one", "expires_at": _FUTURE}

        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request", side_effect=fake_request):
            self.assertEqual(github_app.installation_token(), "ghs_one")

    def test_no_resolvable_installation_raises(self):
        env = {k: v for k, v in _APP_ENV.items() if k != "GH_APP_INSTALLATION_ID"}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request", return_value=[]):  # 0 installs
            with self.assertRaises(github_app.GithubAppError):
                github_app.installation_token()

    def test_mint_failure_raises(self):
        with mock.patch.dict(os.environ, _APP_ENV, clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request", return_value=None):  # API failed
            with self.assertRaises(github_app.GithubAppError):
                github_app.installation_token()


class TestConfigPath(unittest.TestCase):
    def test_config_path_is_under_saw(self):
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/tmp/xdg-saw-test"}, clear=False):
            self.assertEqual(github_app.config_path(),
                             Path("/tmp/xdg-saw-test/saw/github-app.json"))
            self.assertEqual(github_app.legacy_config_path(),
                             Path("/tmp/xdg-saw-test/stayawake/github-app.json"))

    def test_migrates_legacy_stayawake_config(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            xdg = Path(td)
            legacy = xdg / "stayawake" / "github-app.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text(json.dumps({
                "app_id": "1", "private_key_pem": "PEM", "installation_id": "9",
                "slug": "stayawakebot", "name": "StayAwakeBot",
            }), encoding="utf-8")
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": td}, clear=False):
                cfg = github_app.load_config()
            self.assertEqual(cfg["app_id"], "1")
            self.assertTrue((xdg / "saw" / "github-app.json").is_file())
            self.assertFalse(legacy.is_file())


class TestMissingExtra(unittest.TestCase):
    def test_build_jwt_without_pyjwt_points_at_extra(self):
        real_import = builtins.__import__

        def no_jwt(name, *a, **k):
            if name == "jwt":
                raise ImportError("no module named jwt")
            return real_import(name, *a, **k)

        with mock.patch.object(builtins, "__import__", side_effect=no_jwt):
            with self.assertRaises(github_app.GithubAppError) as ctx:
                github_app._build_jwt("123", "KEY")
        self.assertIn(github_app.app_crypto_install_hint(), str(ctx.exception))


class TestResolveTokenIntegration(unittest.TestCase):
    def test_app_token_used_when_no_env_pat(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(github_app, "installation_token", return_value="ghs_app"), \
             mock.patch.object(auth, "gh_token", return_value=None):
            self.assertEqual(auth.resolve_token(), ("ghs_app", "github-app"))

    def test_env_pat_beats_app(self):
        with mock.patch.dict(os.environ, {"GH_SECURITY_TOKEN": "pat"}, clear=True), \
             mock.patch.object(github_app, "installation_token") as inst:
            self.assertEqual(auth.resolve_token(), ("pat", "GH_SECURITY_TOKEN"))
            inst.assert_not_called()   # env PAT wins; App never consulted

    def test_app_error_falls_through_to_none(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(github_app, "installation_token",
                               side_effect=github_app.GithubAppError("boom")), \
             mock.patch.object(auth, "gh_token", return_value=None):
            self.assertEqual(auth.resolve_token(), (None, None))

    def test_non_apperror_from_app_never_crashes_resolution(self):
        # #1287: installation_token raising a NON-GithubAppError (e.g. the json.loads(None) TypeError
        # that shipped in 0.1.17) must NOT crash resolve_token — it degrades and falls through.
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(github_app, "installation_token",
                               side_effect=TypeError("json.loads(None) style crash")), \
             mock.patch.object(auth, "gh_token", return_value="ghtok"):
            self.assertEqual(auth.resolve_token(), ("ghtok", "gh"))


class TestAppCryptoRobustness(unittest.TestCase):
    """#1287: the App-crypto-absent path must NEVER crash the CLI, and readiness must be honest."""

    def test_editable_probe_survives_none_read(self):
        # THE crash root: importlib.metadata `read_text` returns None (a normal, non-editable install
        # has no direct_url.json); `json.loads(None)` used to raise an uncaught TypeError that crashed
        # `saw auth` for every default-install user (no PyJWT).
        class _NoDirectUrl:
            def read_text(self, name):
                return None
        self.assertFalse(github_app._distribution_is_editable(_NoDirectUrl()))

    def test_install_hint_never_raises(self):
        # The hint runs inside error/status paths — any probe failure must degrade, never crash.
        with mock.patch.object(github_app, "distribution", side_effect=RuntimeError("boom")):
            self.assertEqual(github_app.app_crypto_install_hint(), github_app.APP_EXTRA_HINT)

    def test_build_jwt_without_crypto_backend_points_at_extra(self):
        # PyJWT installed WITHOUT `cryptography` → jwt.encode(RS256) raises NotImplementedError; must
        # surface the friendly "install the extra" GithubAppError, not an uncaught crash at mint.
        import types
        real_import = builtins.__import__
        fake_jwt = types.SimpleNamespace(
            encode=lambda *a, **k: (_ for _ in ()).throw(NotImplementedError("Algorithm not supported")))

        def imp(name, *a, **k):
            return fake_jwt if name == "jwt" else real_import(name, *a, **k)

        with mock.patch.object(builtins, "__import__", side_effect=imp):
            with self.assertRaises(github_app.GithubAppError) as ctx:
                github_app._build_jwt("123", "KEY")
        self.assertIn("crypto", str(ctx.exception).lower())

    def test_jwt_available_false_when_pyjwt_absent(self):
        real_import = builtins.__import__

        def no_jwt(name, *a, **k):
            if name == "jwt" or name.startswith("jwt."):
                raise ImportError("no jwt")
            return real_import(name, *a, **k)

        with mock.patch.object(builtins, "__import__", side_effect=no_jwt):
            self.assertFalse(github_app.jwt_available())

    def test_jwt_available_tracks_has_crypto(self):
        try:
            import jwt.algorithms as _alg
        except ImportError:
            self.skipTest("PyJWT not installed")
        with mock.patch.object(_alg, "has_crypto", False):
            self.assertFalse(github_app.jwt_available())   # bare pyjwt, no RS256 → not ready
        with mock.patch.object(_alg, "has_crypto", True):
            self.assertTrue(github_app.jwt_available())


class TestInstallationRepos(unittest.TestCase):
    def test_list_installation_repos_paginates_and_skips_archived(self):
        from stayawake.lib.adapters import github_api
        page1 = {"repositories": [{"full_name": f"o/r{i}"} for i in range(100)]}
        page2 = {"repositories": [{"full_name": "o/last"}, {"full_name": "o/arch", "archived": True}]}
        pages = [page1, page2]
        with mock.patch.object(github_api, "request", side_effect=lambda *a, **k: pages.pop(0)):
            repos = github_api.list_installation_repos("ghs_inst")
        self.assertIn("o/r0", repos)
        self.assertIn("o/last", repos)
        self.assertNotIn("o/arch", repos)          # archived skipped by default
        self.assertEqual(len(repos), 101)


if __name__ == "__main__":
    unittest.main()
