#!/usr/bin/env python3
"""Authority to rewrite history + per-ref protection (`lib/git/authority`).

Every test stubs the GitHub adapter's typed core (`github_api._do_request`), so nothing here
touches the network; the stub routes by exact API path and FAILS on any path the module was not
expected to call, which pins the endpoints as firmly as the answers.

Both properties under test are safety properties, so each is asserted from both sides: `push` must
not become authority, and an unreadable protection rule must not become "not protected".
"""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.lib.adapters import github_api
from stayawake.lib.adapters.github_api import ApiRead
from stayawake.lib.git import authority

_SLUG = "acme/widget"
_REPO = "/repos/acme/widget"
_BRANCH = "/repos/acme/widget/branches/main"
_RULE = "/repos/acme/widget/branches/main/protection"
_USER = "/user"
_TOKEN = "ghp_secret_value_never_logged"


def _routes(by_path: dict[str, ApiRead] | None = None):
    """Stub `_do_request`, routing by exact API path; an unrouted path fails the test."""
    paths = by_path or {}

    def _do_request(path, method="GET", token=None, data=None):
        if path not in paths:
            raise AssertionError(f"unexpected API path: {path}")
        return paths[path]

    return mock.patch.object(github_api, "_do_request", side_effect=_do_request)


def _repo_read(owner_login="acme", permissions=None, include_permissions=True) -> ApiRead:
    body: dict = {"full_name": _SLUG, "owner": {"login": owner_login}}
    if include_permissions:
        body["permissions"] = permissions if permissions is not None else {
            "admin": False, "maintain": False, "push": True, "triage": True, "pull": True}
    return ApiRead(value=body)


def _user_read(login="someone") -> ApiRead:
    return ApiRead(value={"login": login})


def _paths(stub) -> list[str]:
    return [call.args[0] for call in stub.call_args_list]


class TestMayRewrite(unittest.TestCase):
    def test_owner_login_matching_repo_owner_is_authority(self):
        with _routes({_REPO: _repo_read(owner_login="acme"), _USER: _user_read("acme")}) as stub:
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertTrue(got.permitted)
        self.assertEqual(got.reason, "owner")
        self.assertTrue(got.conclusive)
        self.assertEqual(set(_paths(stub)), {_REPO, _USER})

    def test_owner_match_is_case_insensitive(self):
        with _routes({_REPO: _repo_read(owner_login="AcMe"), _USER: _user_read("acme")}):
            self.assertTrue(authority.may_rewrite(_SLUG, _TOKEN).permitted)

    def test_owner_wins_even_without_a_permissions_block(self):
        with _routes({_REPO: _repo_read(owner_login="acme", include_permissions=False),
                      _USER: _user_read("acme")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertTrue(got.permitted)
        self.assertEqual(got.reason, "owner")

    def test_admin_without_ownership_is_authority(self):
        with _routes({_REPO: _repo_read(permissions={"admin": True, "push": True, "pull": True}),
                      _USER: _user_read("contractor")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertTrue(got.permitted)
        self.assertEqual(got.reason, "admin")
        self.assertEqual(got.login, "contractor")

    def test_push_only_is_refused_conclusively(self):
        with _routes({_REPO: _repo_read(permissions={"admin": False, "push": True, "pull": True}),
                      _USER: _user_read("contributor")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "push_without_admin")
        self.assertTrue(got.conclusive)

    def test_maintain_without_admin_is_refused(self):
        # 'maintain' is the closest non-admin role and still may not rewrite history.
        with _routes({_REPO: _repo_read(permissions={"admin": False, "maintain": True,
                                                     "push": True}),
                      _USER: _user_read("maintainer")}):
            self.assertFalse(authority.may_rewrite(_SLUG, _TOKEN).permitted)

    def test_read_only_is_refused(self):
        with _routes({_REPO: _repo_read(permissions={"admin": False, "push": False, "pull": True}),
                      _USER: _user_read("reader")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "no_admin_permission")

    def test_admin_must_be_the_boolean_true(self):
        with _routes({_REPO: _repo_read(permissions={"admin": "true", "push": True}),
                      _USER: _user_read("stranger")}):
            self.assertFalse(authority.may_rewrite(_SLUG, _TOKEN).permitted)

    def test_no_permissions_block_is_refused_but_not_conclusive(self):
        with _routes({_REPO: _repo_read(owner_login="acme", include_permissions=False),
                      _USER: _user_read("stranger")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "permissions_unknown")
        self.assertFalse(got.conclusive)

    def test_forbidden_is_refused_but_not_conclusive(self):
        with _routes({_REPO: ApiRead(cause="forbidden", status=403,
                                     detail="Resource not accessible")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "forbidden")
        self.assertFalse(got.conclusive)

    def test_not_found_is_refused_but_not_conclusive(self):
        with _routes({_REPO: ApiRead(cause="not_found", status=404)}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "not_found")
        self.assertFalse(got.conclusive)

    def test_rate_limited_is_its_own_reason(self):
        with _routes({_REPO: ApiRead(cause="rate_limited", status=403, retry_after=42)}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "rate_limited")
        self.assertFalse(got.conclusive)

    def test_network_failure_is_refused_but_not_conclusive(self):
        with _routes({_REPO: ApiRead(cause="network", detail="[Errno 8] nodename nor servname")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "network_error")
        self.assertFalse(got.conclusive)

    def test_unauthorized_is_refused_but_not_conclusive(self):
        with _routes({_REPO: ApiRead(cause="unauthorized", status=401)}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertEqual(got.reason, "unauthorized")
        self.assertFalse(got.conclusive)

    def test_non_object_repo_body_is_refused(self):
        with _routes({_REPO: ApiRead(value=["not", "a", "repo"])}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "unreadable_repo")
        self.assertFalse(got.conclusive)

    def test_identity_unreadable_falls_through_to_admin(self):
        # An App installation token is FORBIDDEN from GET /user; it must still qualify via admin.
        with _routes({_REPO: _repo_read(permissions={"admin": True, "push": True}),
                      _USER: ApiRead(cause="forbidden", status=403)}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertTrue(got.permitted)
        self.assertEqual(got.reason, "admin")
        self.assertIsNone(got.login)

    def test_identity_unreadable_without_admin_is_refused(self):
        with _routes({_REPO: _repo_read(permissions={"admin": False, "push": True}),
                      _USER: ApiRead(cause="forbidden", status=403)}):
            self.assertFalse(authority.may_rewrite(_SLUG, _TOKEN).permitted)

    def test_no_token_is_refused_without_any_api_call(self):
        with _routes():
            got = authority.may_rewrite(_SLUG, None)
        self.assertFalse(got.permitted)
        self.assertEqual(got.reason, "no_credential")

    def test_malformed_slug_is_refused_without_any_api_call(self):
        for slug in ("widget", "a/b/c", "/widget", "acme/", "", "acme /widget"):
            with self.subTest(slug=slug), _routes():
                got = authority.may_rewrite(slug, _TOKEN)
                self.assertFalse(got.permitted)
                self.assertEqual(got.reason, "malformed_slug")


class TestRefProtection(unittest.TestCase):
    def test_protected_branch_with_readable_rule(self):
        with _routes({_BRANCH: ApiRead(value={"name": "main", "protected": True}),
                      _RULE: ApiRead(value={"required_signatures": {"enabled": True},
                                            "allow_force_pushes": {"enabled": False},
                                            "lock_branch": {"enabled": False}})}) as stub:
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertTrue(got.protected)
        self.assertTrue(got.requires_signed_commits)
        self.assertFalse(got.allows_force_push)
        self.assertEqual(got.reason, "rule_read")
        self.assertFalse(got.undetermined)
        self.assertEqual(_paths(stub), [_BRANCH, _RULE])

    def test_rule_allowing_force_push_is_reported_as_allowed(self):
        with _routes({_BRANCH: ApiRead(value={"protected": True}),
                      _RULE: ApiRead(value={"required_signatures": {"enabled": False},
                                            "allow_force_pushes": {"enabled": True}})}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertTrue(got.allows_force_push)
        self.assertFalse(got.requires_signed_commits)

    def test_locked_branch_forbids_force_push_whatever_the_force_flag_says(self):
        with _routes({_BRANCH: ApiRead(value={"protected": True}),
                      _RULE: ApiRead(value={"lock_branch": {"enabled": True},
                                            "allow_force_pushes": {"enabled": True}})}):
            self.assertFalse(authority.ref_protection(_SLUG, "main", _TOKEN).allows_force_push)

    def test_absent_rule_keys_are_unknown_not_false(self):
        with _routes({_BRANCH: ApiRead(value={"protected": True}),
                      _RULE: ApiRead(value={"required_status_checks": {"strict": True}})}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertTrue(got.protected)
        self.assertIsNone(got.requires_signed_commits)
        self.assertIsNone(got.allows_force_push)

    def test_unprotected_branch_is_known_unprotected_with_unknown_rules(self):
        with _routes({_BRANCH: ApiRead(value={"name": "main", "protected": False})}) as stub:
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertIs(got.protected, False)
        self.assertEqual(got.reason, "not_protected")
        self.assertFalse(got.undetermined)
        # A ruleset can still require signatures / block force-pushes, so those stay unknown.
        self.assertIsNone(got.requires_signed_commits)
        self.assertIsNone(got.allows_force_push)
        self.assertEqual(_paths(stub), [_BRANCH])

    def test_rule_unreadable_without_admin_keeps_protected_true(self):
        with _routes({_BRANCH: ApiRead(value={"protected": True}),
                      _RULE: ApiRead(cause="forbidden", status=403,
                                     detail="Must have admin rights to Repository.")}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertTrue(got.protected)
        self.assertEqual(got.reason, "rule_unreadable")
        self.assertIsNone(got.requires_signed_commits)
        self.assertIsNone(got.allows_force_push)
        self.assertFalse(got.undetermined)

    def test_rule_404_keeps_protected_true_with_unknown_rule(self):
        with _routes({_BRANCH: ApiRead(value={"protected": True}),
                      _RULE: ApiRead(cause="not_found", status=404)}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertTrue(got.protected)
        self.assertEqual(got.reason, "rule_unreadable")

    def test_branch_read_403_is_unknown_never_unprotected(self):
        with _routes({_BRANCH: ApiRead(cause="forbidden", status=403)}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertIsNone(got.protected)
        self.assertTrue(got.undetermined)
        self.assertEqual(got.reason, "forbidden")

    def test_branch_read_404_is_unknown_never_unprotected(self):
        with _routes({_BRANCH: ApiRead(cause="not_found", status=404)}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertIsNone(got.protected)
        self.assertTrue(got.undetermined)
        self.assertEqual(got.reason, "not_found")

    def test_rate_limited_branch_read_is_unknown(self):
        with _routes({_BRANCH: ApiRead(cause="rate_limited", retry_after=30)}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertIsNone(got.protected)
        self.assertEqual(got.reason, "rate_limited")

    def test_network_failure_is_unknown_never_unprotected(self):
        with _routes({_BRANCH: ApiRead(cause="network", detail="timed out")}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertIsNone(got.protected)
        self.assertTrue(got.undetermined)
        self.assertEqual(got.reason, "network_error")

    def test_branch_object_without_a_protected_field_is_unknown(self):
        with _routes({_BRANCH: ApiRead(value={"name": "main"})}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertIsNone(got.protected)
        self.assertEqual(got.reason, "protection_absent")

    def test_non_object_branch_body_is_unknown(self):
        with _routes({_BRANCH: ApiRead(value=["nope"])}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertIsNone(got.protected)
        self.assertEqual(got.reason, "unreadable_branch")

    def test_slashed_branch_keeps_its_separator_in_the_path(self):
        path = "/repos/acme/widget/branches/release/1.0"
        with _routes({path: ApiRead(value={"protected": False})}) as stub:
            authority.ref_protection(_SLUG, "release/1.0", _TOKEN)
        self.assertEqual(_paths(stub), [path])

    def test_malformed_inputs_are_unknown_without_any_api_call(self):
        with _routes():
            self.assertEqual(authority.ref_protection("widget", "main", _TOKEN).reason,
                             "malformed_slug")
            self.assertEqual(authority.ref_protection(_SLUG, "", _TOKEN).reason,
                             "malformed_branch")
            self.assertIsNone(authority.ref_protection("widget", "main", _TOKEN).protected)


class TestNoSecretEscapes(unittest.TestCase):
    """The credential must not reach a result field, and remote text must not be copied through."""

    def test_token_is_absent_from_every_authority_field(self):
        with _routes({_REPO: ApiRead(cause="forbidden", status=403,
                                     detail=f"denied for {_TOKEN}")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertNotIn(_TOKEN, repr(got))

    def test_token_is_absent_from_every_protection_field(self):
        with _routes({_BRANCH: ApiRead(cause="network",
                                       detail=f"failed: Authorization=Bearer {_TOKEN}")}):
            got = authority.ref_protection(_SLUG, "main", _TOKEN)
        self.assertNotIn(_TOKEN, repr(got))

    def test_remote_response_body_is_not_copied_into_the_detail(self):
        with _routes({_REPO: ApiRead(cause="http_error", status=500,
                                     detail="<injected remote text>")}):
            got = authority.may_rewrite(_SLUG, _TOKEN)
        self.assertNotIn("injected remote text", got.detail)
        self.assertEqual(got.reason, "api_error")

    def test_the_token_is_forwarded_as_a_keyword_never_a_url_segment(self):
        seen: list[tuple] = []

        def _do_request(path, method="GET", token=None, data=None):
            seen.append((path, token))
            return ApiRead(cause="not_found")

        with mock.patch.object(github_api, "_do_request", side_effect=_do_request):
            authority.may_rewrite(_SLUG, _TOKEN)
        self.assertTrue(seen)
        for path, token in seen:
            self.assertNotIn(_TOKEN, path)
            self.assertEqual(token, _TOKEN)


if __name__ == "__main__":
    unittest.main()
