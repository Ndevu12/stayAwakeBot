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


class TestRunnerPersistence(unittest.TestCase):
    def test_installed_runner_is_a_warning(self):
        with mock.patch.object(hygiene, "_installed_runner_dir",
                               return_value=Path("/home/u/actions-runner")), \
             mock.patch.object(hygiene, "_runner_services", return_value=[]):
            issues = hygiene.check_runner_persistence()
        self.assertIn("self-hosted-runner-persistence", [i.id for i in issues])
        self.assertTrue(all(i.severity == "warning" for i in issues))

    def test_registered_service_alone_is_detected(self):
        with mock.patch.object(hygiene, "_installed_runner_dir", return_value=None), \
             mock.patch.object(hygiene, "_runner_services",
                               return_value=["actions.runner.org-repo.host"]):
            ids = [i.id for i in hygiene.check_runner_persistence()]
        self.assertEqual(ids, ["self-hosted-runner-persistence"])

    def test_wiper_service_is_a_distinct_warning(self):
        with mock.patch.object(hygiene, "_installed_runner_dir", return_value=None), \
             mock.patch.object(hygiene, "_runner_services",
                               return_value=["gh-token-monitor.service"]):
            ids = [i.id for i in hygiene.check_runner_persistence()]
        self.assertIn("wiper-service-present", ids)

    def test_remediation_is_wiper_safe(self):
        # Must sequence rotation LAST and never tell the user to rotate first — rotating while
        # the runner/wiper persistence is live can trip the home-dir wiper (#1088 ordering).
        with mock.patch.object(hygiene, "_installed_runner_dir",
                               return_value=Path("/home/u/actions-runner")), \
             mock.patch.object(hygiene, "_runner_services",
                               return_value=["gh-token-monitor.service"]):
            issues = hygiene.check_runner_persistence()
        self.assertEqual({"self-hosted-runner-persistence", "wiper-service-present"},
                         {i.id for i in issues})
        for i in issues:
            rem = i.remediation.lower()
            self.assertIn("do not rotate credentials", rem)          # leads with the guardrail
            self.assertTrue("rotate credentials last" in rem or "only then rotate" in rem)
            # The rotation ACTION (the LAST 'rotate' — not the "Do NOT rotate" guardrail) is
            # sequenced AFTER isolation: a meaningful ordering check, not a phrase that never appears.
            self.assertLess(rem.index("isolate the host"), rem.rindex("rotate"))

    def test_macos_launchd_wiper_is_captured(self):
        # Regression: the launchd branch must collect the gh-token-monitor wiper label too, not
        # only actions.runner labels — the safety-critical wiper must not be Linux-only.
        def fake_run(cmd, **kw):
            if cmd[0] == "launchctl":
                return mock.Mock(returncode=0,
                                 stdout="-\t0\tgh-token-monitor\n"
                                        "501\t0\tactions.runner.acme-app.buildbox\n")
            raise FileNotFoundError                       # no systemctl on macOS
        with mock.patch.object(hygiene.subprocess, "run", side_effect=fake_run):
            services = hygiene._runner_services()
        self.assertIn("gh-token-monitor", services)
        self.assertIn("actions.runner.acme-app.buildbox", services)

    def test_service_label_matcher_precision(self):
        # Runner/wiper labels match; an unrelated label that merely CONTAINS "actions.runner"
        # (a third-party helper) must NOT — the old whole-line substring test over-matched.
        self.assertTrue(hygiene._is_runner_or_wiper("actions.runner.acme-app.host"))
        self.assertTrue(hygiene._is_runner_or_wiper("gh-token-monitor.service"))
        self.assertFalse(hygiene._is_runner_or_wiper("com.vendor.actions.runner-helper"))
        self.assertFalse(hygiene._is_runner_or_wiper("com.apple.Spotlight"))

    def test_clean_host_has_no_runner_issue(self):
        with mock.patch.object(hygiene, "_installed_runner_dir", return_value=None), \
             mock.patch.object(hygiene, "_runner_services", return_value=[]):
            self.assertEqual(hygiene.check_runner_persistence(), [])

    def test_runner_persistence_triggers_incident_runbook(self):
        # Host persistence is an INCIDENT_TRIGGER, so render() must lead with the rotate-LAST
        # runbook (a user's reflex on seeing a rogue runner is to rotate — the wiper tripwire).
        issue = hygiene.HygieneIssue("self-hosted-runner-persistence", "warning", "T", "D", "F")
        out = hygiene.render([issue]).lower()
        self.assertIn("rotate last", out)
        self.assertLess(out.index("isolate the host"), out.index("rotate credentials"))

    def test_audit_composes_runner_persistence(self):
        # Regression: audit() is the SINGLE composition site and must include the runner probe,
        # so a probe added there is never silently dropped by a caller that hand-assembles checks.
        sentinel = hygiene.HygieneIssue("self-hosted-runner-persistence", "warning", "T", "D", "F")
        with mock.patch.object(hygiene, "check_credentials", return_value=[]), \
             mock.patch.object(hygiene, "check_vscode", return_value=[]), \
             mock.patch.object(hygiene, "check_branch_protection", return_value=[]), \
             mock.patch.object(hygiene, "check_runner_persistence", return_value=[sentinel]):
            ids = [i.id for i in hygiene.audit()]
        self.assertIn("self-hosted-runner-persistence", ids)


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
