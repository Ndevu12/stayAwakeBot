#!/usr/bin/env python3
"""GitHub App auth: installation-token minting, caching, graceful degradation.

JWT signing is BUILT IN (stdlib RS256 signer, `lib/jwtsign`) — no optional crypto extra — so these
tests mock the signing seam for minting/caching, and exercise the real signer's fail-loud path with a
malformed key.
"""
from __future__ import annotations

import json
import os
import stat
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


class TestMultiAccountMinting(unittest.TestCase):
    """A GitHub App is per-account: `installation_token(repo_slug)` resolves the installation that
    OWNS the repo and mints ITS token, so one App installed on several accounts/orgs services them all."""

    def setUp(self):
        github_app._cache.clear()
        github_app._token_perms.clear()
        github_app._owner_installation.clear()
        self._cfg = mock.patch.object(github_app, "load_config",
                                      return_value={"slug": "stayawakebot"})
        self._cfg.start()

    def tearDown(self):
        self._cfg.stop()

    def test_resolves_owner_installation_and_mints(self):
        calls: list[str] = []

        def fake_request(path, method="GET", token=None, data=None, quiet=False):
            calls.append(path)
            if path == "/repos/UB-TechDEV/backend/installation":
                return {"id": 555}
            if path == "/app/installations/555/access_tokens":
                return {"token": "ghs_org", "expires_at": _FUTURE}
            raise AssertionError(f"unexpected {path}")

        with mock.patch.dict(os.environ, {"GH_APP_ID": "123", "GH_APP_PRIVATE_KEY": "-----PEM-----"},
                             clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request", side_effect=fake_request):
            self.assertEqual(github_app.installation_token("UB-TechDEV/backend"), "ghs_org")
        self.assertIn("/repos/UB-TechDEV/backend/installation", calls)

    def test_all_repos_install_reuses_without_relookup(self):
        # An "all repositories" install → every repo of the owner is reachable, so the per-owner memo
        # is reused: two repos → ONE reachability lookup and ONE mint (no wasted per-repo calls).
        n = {"install_lookups": 0, "mints": 0}

        def fake_request(path, method="GET", token=None, data=None, quiet=False):
            if path.endswith("/installation"):
                n["install_lookups"] += 1
                return {"id": 555, "repository_selection": "all"}
            if "access_tokens" in path:
                n["mints"] += 1
                return {"token": "ghs_org", "expires_at": _FUTURE}
            raise AssertionError(path)

        with mock.patch.dict(os.environ, {"GH_APP_ID": "123", "GH_APP_PRIVATE_KEY": "-----PEM-----"},
                             clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request", side_effect=fake_request):
            github_app.installation_token("org/one")
            github_app.installation_token("org/two")       # same all-repos install → memo reused
        self.assertEqual(n["install_lookups"], 1)           # all-repos → resolved once, reused
        self.assertEqual(n["mints"], 1)                     # installation token cached across repos

    def test_select_repos_checks_each_repo_and_rejects_excluded(self):
        # A "select repositories" install → reachability differs per repo, so the memo must NOT
        # short-circuit: repo A (selected) resolves; repo B (same owner, NOT selected) must still
        # 404 → GithubAppError, never silently reuse A's installation.
        n = {"install_lookups": 0}

        def fake_request(path, method="GET", token=None, data=None, quiet=False):
            if path == "/repos/org/selected/installation":
                n["install_lookups"] += 1
                return {"id": 555, "repository_selection": "selected"}
            if path == "/repos/org/excluded/installation":
                n["install_lookups"] += 1
                return None                                 # 404 — not in the select-repos install
            if "access_tokens" in path:
                return {"token": "ghs_org", "expires_at": _FUTURE}
            raise AssertionError(path)

        with mock.patch.dict(os.environ, {"GH_APP_ID": "123", "GH_APP_PRIVATE_KEY": "-----PEM-----"},
                             clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request", side_effect=fake_request):
            self.assertEqual(github_app.installation_token("org/selected"), "ghs_org")
            with self.assertRaises(github_app.GithubAppError):
                github_app.installation_token("org/excluded")
        self.assertEqual(n["install_lookups"], 2)           # select-repos → each repo checked, no skip

    def test_app_not_installed_on_owner_raises_with_install_guidance(self):
        def fake_request(path, method="GET", token=None, data=None, quiet=False):
            if path.endswith("/installation"):
                return None                                 # 404 — App not installed on that owner
            raise AssertionError(path)

        with mock.patch.dict(os.environ, {"GH_APP_ID": "123", "GH_APP_PRIVATE_KEY": "-----PEM-----"},
                             clear=True), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "request", side_effect=fake_request):
            with self.assertRaises(github_app.GithubAppError) as ctx:
                github_app.installation_token("SomeOrg/repo")
        msg = str(ctx.exception)
        self.assertIn("SomeOrg", msg)
        self.assertIn("apps/stayawakebot/installations/new", msg)


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
            dest = xdg / "saw" / "github-app.json"
            self.assertTrue(dest.is_file())
            self.assertFalse(legacy.is_file())
            # #1288: the migrated PRIVATE-KEY file must be 0600 (no group/world bits).
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode) & (stat.S_IRWXG | stat.S_IRWXO), 0)

    def test_save_config_writes_0600_in_0700_dir_no_readable_window(self):
        # #1288: the file holds the App PRIVATE KEY; it must be written 0600 with NO group/world
        # bits (write-then-chmod left a world-readable window) under a 0700 dir. Verified across a
        # fresh write AND overwriting an existing (possibly looser-mode) file.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            xdg = Path(td)
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": td}, clear=False):
                p = github_app.save_config("1", "-----BEGIN KEY-----\nSECRET\n-----END KEY-----",
                                           installation_id="9", slug="saw")
                self.assertEqual(stat.S_IMODE(p.stat().st_mode) & (stat.S_IRWXG | stat.S_IRWXO), 0,
                                 "private-key file must have no group/world bits")
                self.assertEqual(stat.S_IMODE(p.parent.stat().st_mode) & (stat.S_IRWXG | stat.S_IRWXO),
                                 0, "config dir must not be world-traversable")
                # Loosen it, then re-save: the overwrite must restore 0600 (atomic replace).
                os.chmod(p, 0o644)
                github_app.save_config("2", "-----BEGIN KEY-----\nS2\n-----END KEY-----")
                self.assertEqual(stat.S_IMODE(p.stat().st_mode) & (stat.S_IRWXG | stat.S_IRWXO), 0)
                # No leftover temp files in the config dir.
                self.assertFalse([f for f in p.parent.iterdir() if f.name.startswith(".github-app-")])


class TestBuiltInSigning(unittest.TestCase):
    def test_jwt_always_available(self):
        # Signing is built in (no optional extra) → the capability is always present.
        self.assertTrue(github_app.jwt_available())

    def test_build_jwt_with_malformed_key_raises_apperror(self):
        # A genuinely unusable key (not a PEM) must surface as a friendly GithubAppError, not a raw
        # crash — the built-in signer's JwtSignError is wrapped at the mint boundary.
        with self.assertRaises(github_app.GithubAppError):
            github_app._build_jwt("123", "not a private key")

    def test_build_jwt_signs_a_real_key(self):
        # End-to-end through the real built-in signer: a valid RSA PEM yields a 3-segment JWT whose
        # payload carries the App id as `iss`.
        import base64
        import json as _json
        import shutil
        import subprocess
        import tempfile
        if not shutil.which("openssl"):
            self.skipTest("needs openssl to generate a key")
        with tempfile.TemporaryDirectory() as td:
            key = Path(td) / "k.pem"
            subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"],
                           check=True, capture_output=True)
            jwt = github_app._build_jwt("123", key.read_text())
        parts = jwt.split(".")
        self.assertEqual(len(parts), 3)
        payload = _json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        self.assertEqual(payload["iss"], "123")


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


class TestAppExists(unittest.TestCase):
    """`app_exists()` distinguishes 'App still on GitHub' from 'deleted' from 'can't tell' so
    register can avoid duplicating a live App yet recover when the old one is genuinely gone."""

    def test_true_when_app_authenticates(self):
        with mock.patch.dict(os.environ, {"GH_APP_ID": "1", "GH_APP_PRIVATE_KEY": "PEM"}, clear=True), \
             mock.patch.object(github_app, "load_config", return_value=None), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "app_authenticated", return_value=True):
            self.assertTrue(github_app.app_exists())

    def test_false_when_app_gone(self):
        with mock.patch.dict(os.environ, {"GH_APP_ID": "1", "GH_APP_PRIVATE_KEY": "PEM"}, clear=True), \
             mock.patch.object(github_app, "load_config", return_value=None), \
             mock.patch.object(github_app, "_build_jwt", return_value="JWT"), \
             mock.patch.object(github_app.github_api, "app_authenticated", return_value=False):
            self.assertFalse(github_app.app_exists())

    def test_none_when_not_configured(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(github_app, "load_config", return_value=None):
            self.assertIsNone(github_app.app_exists())


class TestAppAuthenticated(unittest.TestCase):
    def test_true_on_app_object(self):
        from stayawake.lib.adapters import github_api
        from stayawake.lib.adapters.github_api import ApiRead
        with mock.patch.object(github_api, "_do_request", return_value=ApiRead(value={"id": 42})):
            self.assertTrue(github_api.app_authenticated("JWT"))

    def test_false_only_on_404_gone(self):
        from stayawake.lib.adapters import github_api
        from stayawake.lib.adapters.github_api import ApiRead
        with mock.patch.object(github_api, "_do_request", return_value=ApiRead(cause="not_found")):
            self.assertFalse(github_api.app_authenticated("JWT"))

    def test_none_on_401_not_false(self):
        # A 401 (bad/expired key, or clock skew) must NOT be read as "App deleted" — that would let a
        # transient error trigger a duplicate App. Stay cautious → None.
        from stayawake.lib.adapters import github_api
        from stayawake.lib.adapters.github_api import ApiRead
        with mock.patch.object(github_api, "_do_request", return_value=ApiRead(cause="unauthorized")):
            self.assertIsNone(github_api.app_authenticated("JWT"))

    def test_none_on_403_secondary_ratelimit(self):
        # A secondary rate-limit is a 403 (classified 'forbidden'); it is NOT proof the App is gone.
        from stayawake.lib.adapters import github_api
        from stayawake.lib.adapters.github_api import ApiRead
        with mock.patch.object(github_api, "_do_request", return_value=ApiRead(cause="forbidden")):
            self.assertIsNone(github_api.app_authenticated("JWT"))

    def test_none_on_network(self):
        from stayawake.lib.adapters import github_api
        from stayawake.lib.adapters.github_api import ApiRead
        with mock.patch.object(github_api, "_do_request", return_value=ApiRead(cause="network")):
            self.assertIsNone(github_api.app_authenticated("JWT"))

    def test_none_without_jwt(self):
        from stayawake.lib.adapters import github_api
        self.assertIsNone(github_api.app_authenticated(None))


if __name__ == "__main__":
    unittest.main()
