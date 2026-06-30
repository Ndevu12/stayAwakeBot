#!/usr/bin/env python3
"""Remote target resolution — the #1075 ladder for `--remote` (no real network).

selectors (users/orgs/slugs) override config → configured targets → infer "my repos"
(owner-only, private-inclusive via /user/repos) or a GitHub App installation. Plus the
owner/repo slug validation that makes `--remote` positionals fail loudly.
"""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security import service
from stayawake.bots.security.targets import ScanOptions
from stayawake.core.adapters import github_api

OPTS = ScanOptions()


class TestRemoteResolution(unittest.TestCase):
    def test_selectors_override_config(self):
        cfg = {"targets": {"github": {"users": ["cfguser"]}}}
        with mock.patch.object(service.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(service.github_api, "list_repos",
                               side_effect=lambda acct, kind, *a, **k: [f"{acct}/r"]) as m:
            slugs, _t, _s = service._resolve_remote(cfg, OPTS, users=["adhoc"], orgs=None, slugs=None)
        self.assertEqual(slugs, ["adhoc/r"])              # the CONFIG user is NOT enumerated
        m.assert_called_once_with("adhoc", "users", "t", False, False)

    def test_slugs_passthrough_no_enumeration(self):
        with mock.patch.object(service.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(service.github_api, "list_repos") as m:
            slugs, _t, _s = service._resolve_remote({}, OPTS, users=None, orgs=None,
                                                    slugs=["o/b", "o/a"])
        self.assertEqual(slugs, ["o/a", "o/b"])          # used as-is (sorted), no API enumeration
        m.assert_not_called()

    def test_infer_my_repos_when_nothing_named(self):
        with mock.patch.object(service.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(service.github_api, "list_my_repos", return_value=["me/a", "me/b"]) as m:
            slugs, _t, _s = service._resolve_remote({}, OPTS, users=None, orgs=None, slugs=None)
        self.assertEqual(slugs, ["me/a", "me/b"])
        m.assert_called_once()                            # /user/repos, owner-only

    def test_github_app_infers_installation_repos(self):
        with mock.patch.object(service.auth, "resolve_token", return_value=("t", "github-app")), \
             mock.patch.object(service.github_api, "list_installation_repos", return_value=["org/a"]), \
             mock.patch.object(service.github_api, "list_my_repos") as my:
            slugs, _t, source = service._resolve_remote({}, OPTS, users=None, orgs=None, slugs=None)
        self.assertEqual(slugs, ["org/a"])
        self.assertEqual(source, "github-app")
        my.assert_not_called()                           # App → installation repos, not /user/repos

    def test_no_token_no_config_is_empty(self):
        with mock.patch.object(service.auth, "resolve_token", return_value=(None, None)):
            slugs, _t, _s = service._resolve_remote({}, OPTS, users=None, orgs=None, slugs=None)
        self.assertEqual(slugs, [])

    def test_invalid_slugs_detected(self):
        self.assertEqual(service.invalid_slugs(["a/b", "bad", "x/y/z", "a/b c"]),
                         ["bad", "x/y/z", "a/b c"])
        self.assertEqual(service.invalid_slugs(["owner/name"]), [])


class TestListMyRepos(unittest.TestCase):
    def test_uses_user_repos_endpoint_owner_affiliation(self):
        calls: list[str] = []

        def fake_request(path, **kw):
            calls.append(path)
            return []                                    # empty → single page

        with mock.patch.object(github_api, "request", side_effect=fake_request):
            github_api.list_my_repos("t")
        # Must hit /user/repos (private-inclusive), NOT /users/{me}/repos (public-only).
        self.assertTrue(any("/user/repos" in p and "affiliation=owner" in p for p in calls), calls)


if __name__ == "__main__":
    unittest.main()
