#!/usr/bin/env python3
"""Local machine hygiene checks (credentials + VS Code), all mocked — no real probing."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hygiene


class TestCredentials(unittest.TestCase):
    def test_keychain_hit_is_a_warning(self):
        with mock.patch.object(hygiene, "_macos_keychain_has_github", return_value=True), \
             mock.patch.object(hygiene, "_git_credentials_file_with_github", return_value=None):
            issues = hygiene.check_credentials()
        ids = [i.id for i in issues]
        self.assertIn("cached-github-keychain", ids)
        self.assertTrue(all(i.severity == "warning" for i in issues))

    def test_clean_machine_has_no_credential_issues(self):
        with mock.patch.object(hygiene, "_macos_keychain_has_github", return_value=False), \
             mock.patch.object(hygiene, "_git_credentials_file_with_github", return_value=None):
            self.assertEqual(hygiene.check_credentials(), [])

    def test_plaintext_git_credentials_detected(self):
        with tempfile.TemporaryDirectory() as d:
            cred = Path(d) / ".git-credentials"
            cred.write_text("https://x:token@github.com\n", encoding="utf-8")
            with mock.patch.object(hygiene.Path, "home", return_value=Path(d)):
                self.assertEqual(hygiene._git_credentials_file_with_github(), cred)

    def test_plaintext_remediation_is_wiper_safe(self):
        # The rotation advice must sequence rotation LAST and name the wiper tripwire —
        # never the old unconditional "rotate the exposed token on GitHub" (#1088).
        with mock.patch.object(hygiene, "_macos_keychain_has_github", return_value=False), \
             mock.patch.object(hygiene, "_git_credentials_file_with_github",
                               return_value=Path("/home/u/.git-credentials")):
            issues = hygiene.check_credentials()
        rem = next(i.remediation for i in issues if i.id == "git-credentials-plaintext")
        self.assertIn("gh-token-monitor.service", rem)          # names the wiper tripwire
        self.assertIn("Rotate the exposed token LAST", rem)     # rotation is sequenced last
        self.assertNotIn("rotate the exposed token on GitHub", rem)  # old unsafe wording gone


class TestVSCode(unittest.TestCase):
    def _settings(self, body: str) -> Path:
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        f.write(body)
        f.close()
        return Path(f.name)

    def test_autotasks_on_is_warning(self):
        p = self._settings('{ "task.allowAutomaticTasks": "on" }')
        ids = [i.id for i in hygiene.check_vscode(p)]
        self.assertIn("vscode-autotasks-on", ids)

    def test_autotasks_off_is_clean(self):
        p = self._settings('{ "task.allowAutomaticTasks": "off" }')
        self.assertEqual(hygiene.check_vscode(p), [])

    def test_missing_setting_is_info(self):
        p = self._settings('{ "editor.fontSize": 13 }')
        issues = hygiene.check_vscode(p)
        self.assertEqual([i.id for i in issues], ["vscode-autotasks-default"])
        self.assertEqual(issues[0].severity, "info")

    def test_workspace_trust_disabled_is_warning(self):
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"security.workspace.trust.enabled": false }')
        ids = [i.id for i in hygiene.check_vscode(p)]
        self.assertIn("vscode-workspace-trust-off", ids)

    def test_no_vscode_settings_is_noop(self):
        # No path given → auto-detect; when VS Code isn't installed it returns None.
        with mock.patch.object(hygiene, "_vscode_user_settings", return_value=None):
            self.assertEqual(hygiene.check_vscode(), [])


class TestBranchProtection(unittest.TestCase):
    def test_noop_without_slug_or_token(self):
        self.assertEqual(hygiene.check_branch_protection(None, "t"), [])
        self.assertEqual(hygiene.check_branch_protection("o/r", None), [])

    def test_unprotected_branch_warns(self):
        with mock.patch("stayawake.core.adapters.github_api.get_branch_protection",
                        return_value=None):
            issues = hygiene.check_branch_protection("o/r", "tok")
        self.assertEqual([i.id for i in issues], ["branch-unprotected"])

    def test_worm_guard_not_required_warns(self):
        prot = {"required_status_checks": {"contexts": ["build", "lint"]}}
        with mock.patch("stayawake.core.adapters.github_api.get_branch_protection",
                        return_value=prot):
            issues = hygiene.check_branch_protection("o/r", "tok")
        self.assertEqual([i.id for i in issues], ["worm-guard-not-required"])

    def test_worm_guard_required_is_clean(self):
        prot = {"required_status_checks": {"contexts": ["Worm Guard — block infected merges"]}}
        with mock.patch("stayawake.core.adapters.github_api.get_branch_protection",
                        return_value=prot):
            self.assertEqual(hygiene.check_branch_protection("o/r", "tok"), [])


class TestAuditRender(unittest.TestCase):
    def test_render_clean(self):
        self.assertIn("no issues", hygiene.render([]))

    def test_render_lists_issues(self):
        issue = hygiene.HygieneIssue("x", "warning", "Title", "Detail", "Fix")
        out = hygiene.render([issue])
        self.assertIn("Title", out)
        self.assertIn("fix: Fix", out)

    def test_render_surfaces_incident_sequence_on_credential_exposure(self):
        issue = hygiene.HygieneIssue("git-credentials-plaintext", "warning", "T", "D", "F")
        out = hygiene.render([issue]).lower()
        self.assertIn("rotate last", out)                              # runbook header
        self.assertLess(out.index("isolate the host"), out.index("rotate credentials"))

    def test_render_omits_incident_sequence_for_non_trigger_issue(self):
        issue = hygiene.HygieneIssue("vscode-autotasks-on", "warning", "T", "D", "F")
        self.assertNotIn("respond in THIS order", hygiene.render([issue]))

    def test_incident_response_sequence_orders_rotation_last(self):
        joined = " ".join(hygiene.incident_response_sequence()).lower()
        self.assertLess(joined.index("isolate"), joined.index("rotate"))
        self.assertLess(joined.index("neutralize"), joined.index("rotate"))
        self.assertIn("gh-token-monitor.service", joined)


if __name__ == "__main__":
    unittest.main()
