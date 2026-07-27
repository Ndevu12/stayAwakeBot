#!/usr/bin/env python3
"""core.identity — capability gate + push failure classification."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.core.identity import (
    Capability, Intent, classify_push_stderr, push_failure_message, require,
)
from stayawake.core.identity.capabilities import (
    capabilities_from_app_permissions, capabilities_from_oauth_scopes,
)
from stayawake.core.identity.session import Session


class TestCapabilities(unittest.TestCase):
    def test_repo_scope_grants_write_but_not_workflows(self):
        caps = capabilities_from_oauth_scopes({"repo"})
        self.assertIn(Capability.CONTENTS_WRITE, caps)
        self.assertIn(Capability.PULL_REQUESTS_WRITE, caps)
        self.assertNotIn(Capability.WORKFLOWS_WRITE, caps)

    def test_workflow_scope_adds_workflows(self):
        caps = capabilities_from_oauth_scopes({"repo", "workflow"})
        self.assertIn(Capability.WORKFLOWS_WRITE, caps)

    def test_app_permissions_map(self):
        caps = capabilities_from_app_permissions({
            "contents": "write", "pull_requests": "write", "workflows": "write",
        })
        self.assertIn(Capability.WORKFLOWS_WRITE, caps)
        self.assertIn(Capability.CONTENTS_WRITE, caps)


class TestGate(unittest.TestCase):
    def test_no_token_denies(self):
        sess = Session(token=None, source=None, kind="none", live=False)
        d = require(Intent.OPEN_GUARD_PR, session=sess)
        self.assertFalse(d.allowed)

    def test_dead_token_denies(self):
        sess = Session(token="t", source="gh", kind="user", live=False)
        d = require(Intent.OPEN_FIX_PR, session=sess)
        self.assertFalse(d.allowed)
        self.assertIn("unreachable", d.message.lower())
        self.assertIn(Capability.CONTENTS_WRITE, d.missing)

    def test_app_live_but_repo_unreachable_does_not_fake_missing_scopes(self):
        # Token works globally; get_repo for this slug fails → old UX listed every write cap.
        sess = Session(
            token="ghs_x", source="github-app", kind="app_installation",
            actor="installation:1 (stayawakebot)", live=False,
            capabilities=frozenset({
                Capability.CONTENTS_WRITE, Capability.PULL_REQUESTS_WRITE,
                Capability.WORKFLOWS_WRITE, Capability.REPO_READ,
            }),
        )
        with mock.patch("stayawake.lib.adapters.github_api.token_is_valid", return_value=True), \
             mock.patch("stayawake.lib.github_app.load_config",
                        return_value={"installation_id": "149", "slug": "stayawakebot"}):
            d = require(Intent.OPEN_GUARD_PR, session=sess, repo_slug="Ndevu12/justdeploy")
        self.assertFalse(d.allowed)
        self.assertEqual(d.missing, frozenset())
        self.assertNotIn("missing:", d.message)
        self.assertIn("justdeploy", d.message)
        self.assertIn("NOT missing write scopes", d.message)
        self.assertTrue(any("installations/149" in (u.command or "") for u in d.upgrades))

    def test_globally_dead_still_reports_capability_gap_shape(self):
        sess = Session(token="dead", source="github-app", kind="app_installation", live=False)
        with mock.patch("stayawake.lib.adapters.github_api.token_is_valid", return_value=False):
            d = require(Intent.OPEN_GUARD_PR, session=sess, repo_slug="o/r")
        self.assertFalse(d.allowed)
        self.assertIn(Capability.WORKFLOWS_WRITE, d.missing)
        self.assertIn("unreachable", d.message.lower())

    def test_repo_without_workflow_allows_fix_denies_guard(self):
        caps = capabilities_from_oauth_scopes({"repo"})
        sess = Session(token="t", source="gh", kind="user", actor="me",
                       capabilities=caps, scopes=frozenset({"repo"}), live=True)
        self.assertTrue(require(Intent.OPEN_FIX_PR, session=sess).allowed)
        guard = require(Intent.OPEN_GUARD_PR, session=sess)
        self.assertFalse(guard.allowed)
        self.assertIn(Capability.WORKFLOWS_WRITE, guard.missing)
        self.assertIn("workflow", guard.message.lower())
        self.assertTrue(any(u.kind == "refresh_gh" for u in guard.upgrades))

    def test_repo_plus_workflow_allows_guard(self):
        caps = capabilities_from_oauth_scopes({"repo", "workflow"})
        sess = Session(token="t", source="gh", kind="user", capabilities=caps, live=True)
        self.assertTrue(require(Intent.OPEN_GUARD_PR, session=sess).allowed)

    def test_unknown_capabilities_allow_after_liveness(self):
        sess = Session(token="t", source="gh", kind="user", capabilities=None, live=True)
        self.assertTrue(require(Intent.OPEN_GUARD_PR, session=sess).allowed)


class TestClassify(unittest.TestCase):
    def test_workflow_scope_message(self):
        f = classify_push_stderr(
            "refusing to allow a Personal Access Token to create or update workflow "
            "`.github/workflows/worm-guard.yml` without `workflow` scope")
        self.assertEqual(f.reason, "workflow_scope")
        self.assertIn("workflow", push_failure_message(f).lower())

    def test_signed_commits(self):
        f = classify_push_stderr("remote rejected: Commit must be signed")
        self.assertEqual(f.reason, "signed_commits")


if __name__ == "__main__":
    unittest.main()
