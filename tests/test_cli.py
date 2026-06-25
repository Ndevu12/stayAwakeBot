#!/usr/bin/env python3
"""Tests for the unified `saw` dispatcher (stayawake.cli).

These verify pure ROUTING — that each verb maps to the right service call with the
right arguments — plus the back-compat guards the redesign promised:
  * no subcommand/alias name collisions (so a future verb can't silently shadow one),
  * legacy flag spellings (--fail-on-findings / --local-only / --open-pr) still parse,
  * the `saw sec <verb>` namespace seam is a transparent no-op today,
  * pyproject keeps all 8 legacy console scripts AND adds saw/stayawake.
The real scanning/remediation functions are mocked; we assert how they are called.
"""
from __future__ import annotations

import argparse
import io
import pathlib
import tomllib
import unittest
from contextlib import redirect_stdout
from unittest import mock

from stayawake import cli


class TestParserIntegrity(unittest.TestCase):
    def _subaction(self):
        parser = cli.build_parser()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                return action
        raise AssertionError("no subparsers action found")

    def test_no_name_or_alias_collisions(self):
        names = list(self._subaction()._name_parser_map.keys())
        self.assertEqual(len(names), len(set(names)), f"duplicate names: {names}")

    def test_all_canonical_verbs_present(self):
        names = self._subaction()._name_parser_map.keys()
        for verb in cli.VERBS:
            self.assertIn(verb, names)


class TestScanRouting(unittest.TestCase):
    @mock.patch("stayawake.bots.security.service.scan", return_value=0)
    def test_flags_map_to_service_signature(self, m):
        rc = cli.main(["scan", "-f", "-L", "-c", "cfg.yml", "./repo", "-p", "extra"])
        self.assertEqual(rc, 0)
        config_path, local_only, fail_on_findings, reports_dir, paths = m.call_args.args
        self.assertEqual(config_path, "cfg.yml")
        self.assertTrue(local_only)
        self.assertTrue(fail_on_findings)
        self.assertIsNone(reports_dir)
        self.assertIn("./repo", paths)
        self.assertIn("extra", paths)

    @mock.patch("stayawake.bots.security.service.scan", return_value=1)
    def test_legacy_flag_aliases_still_parse(self, m):
        rc = cli.main(["scan", "--fail-on-findings", "--local-only"])
        self.assertEqual(rc, 1)
        _, local_only, fail_on_findings, _, _ = m.call_args.args
        self.assertTrue(local_only)
        self.assertTrue(fail_on_findings)

    @mock.patch("stayawake.bots.security.service.scan", return_value=0)
    def test_bare_scan_passes_no_paths(self, m):
        cli.main(["scan"])
        self.assertIsNone(m.call_args.args[4])

    @mock.patch("stayawake.bots.security.service.scan", return_value=0)
    def test_short_alias_routes_to_scan(self, m):
        cli.main(["s", "-f"])
        self.assertTrue(m.call_args.args[2])


class TestSecNamespace(unittest.TestCase):
    @mock.patch("stayawake.bots.security.service.scan", return_value=0)
    def test_leading_sec_token_is_stripped(self, m):
        cli.main(["sec", "scan", "-f"])
        self.assertTrue(m.call_args.args[2])


class TestRunPipeline(unittest.TestCase):
    @mock.patch("stayawake.cli.commands.run.resolve_reports_dir",
                return_value=pathlib.Path("/tmp/r"))
    @mock.patch("stayawake.bots.security.alerter.run")
    @mock.patch("stayawake.bots.security.reporter.generate")
    @mock.patch("stayawake.bots.security.service.scan", return_value=1)
    def test_run_threads_one_reports_dir_and_returns_scan_exit(
            self, m_scan, m_report, m_alert, _resolve):
        rc = cli.main(["run", "-f", "-d", "/tmp/r"])
        self.assertEqual(rc, 1)
        # The pipeline must resolve the reports dir ONCE and feed the same value to
        # the scan (positional 4) and to report/alert, so all three stages agree.
        self.assertEqual(m_scan.call_args.args[3], pathlib.Path("/tmp/r"))
        self.assertEqual(m_report.call_args.kwargs["latest_path"], "/tmp/r/latest.json")
        self.assertEqual(m_alert.call_args.kwargs["latest_path"], "/tmp/r/latest.json")


class TestReportAlert(unittest.TestCase):
    @mock.patch("stayawake.bots.security.reporter.generate")
    def test_report_uses_latest_flag(self, m):
        cli.main(["report", "-l", "x.json"])
        self.assertEqual(m.call_args.kwargs["latest_path"], "x.json")

    @mock.patch("stayawake.bots.security.alerter.run")
    def test_alert_default_latest(self, m):
        cli.main(["alert"])
        self.assertEqual(m.call_args.kwargs["latest_path"], cli.DEFAULT_LATEST)


class TestFix(unittest.TestCase):
    @mock.patch("stayawake.bots.security.remediator.remediate")
    def test_local_apply_pr(self, m):
        rc = cli.main(["fix", "--apply", "--pr"])
        self.assertEqual(rc, 0)
        self.assertEqual(m.call_args.kwargs, {"apply": True, "open_pr": True})

    @mock.patch("stayawake.bots.security.remediator.remediate")
    def test_open_pr_legacy_alias(self, m):
        cli.main(["fix", "--apply", "--open-pr"])
        self.assertTrue(m.call_args.kwargs["open_pr"])

    @mock.patch("stayawake.bots.security.remediator.submit_org_prs", return_value=0)
    def test_remote_routes_to_org_prs(self, m):
        rc = cli.main(["fix", "--remote"])
        self.assertEqual(rc, 0)
        m.assert_called_once()

    @mock.patch("stayawake.bots.security.remediator.submit_org_prs", return_value=3)
    def test_remote_exit_zero_even_when_prs_opened(self, _):
        # submit_org_prs returns a COUNT of repos, not an exit code; a successful
        # sweep that opens 3 PRs must still exit 0, not 3.
        self.assertEqual(cli.main(["fix", "--remote"]), 0)


class TestAudit(unittest.TestCase):
    @mock.patch("stayawake.bots.security.hygiene.render", return_value="")
    @mock.patch("stayawake.bots.security.hygiene.check_branch_protection", return_value=[])
    @mock.patch("stayawake.bots.security.hygiene.check_vscode", return_value=[])
    @mock.patch("stayawake.bots.security.hygiene.check_credentials", return_value=[])
    @mock.patch("stayawake.core.auth.resolve_token", return_value=(None, None))
    def test_clean_audit_returns_zero(self, *_):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["audit"]), 0)

    @mock.patch("stayawake.bots.security.hygiene.render", return_value="")
    @mock.patch("stayawake.bots.security.hygiene.check_branch_protection", return_value=[])
    @mock.patch("stayawake.bots.security.hygiene.check_vscode", return_value=[])
    @mock.patch("stayawake.bots.security.hygiene.check_credentials")
    @mock.patch("stayawake.core.auth.resolve_token", return_value=(None, None))
    def test_fail_flag_gates_on_warning(self, _tok, m_cred, *_):
        warning = mock.Mock()
        warning.severity = "warning"
        m_cred.return_value = [warning]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["audit", "-f"]), 1)


class TestDispatcherOwnedCommands(unittest.TestCase):
    @mock.patch("stayawake.core.auth.resolve_token", return_value=(None, None))
    def test_doctor_runs(self, _):
        with redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main(["doctor"]), 0)
        self.assertIn("saw resolves to", buf.getvalue())

    def test_search_finds_remediation(self):
        with redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main(["search", "open", "a", "pr"]), 0)
        self.assertIn("saw fix", buf.getvalue())

    def test_search_no_match_returns_zero(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["search", "zzzznotacommand"]), 0)

    def test_completion_bash(self):
        with redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main(["completion", "bash"]), 0)
        self.assertIn("complete -F", buf.getvalue())


class TestTopLevel(unittest.TestCase):
    def test_no_command_prints_help(self):
        with redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main([]), 0)
        self.assertIn("usage", buf.getvalue().lower())

    def test_version_exits_zero(self):
        with self.assertRaises(SystemExit) as cm, redirect_stdout(io.StringIO()):
            cli.main(["--version"])
        self.assertEqual(cm.exception.code, 0)


class TestPyprojectScripts(unittest.TestCase):
    def test_entry_points(self):
        data = tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8"))
        scripts = data["project"]["scripts"]
        for legacy in ("stayawake-health-check", "stayawake-health-report",
                       "stayawake-health-alert", "stayawake-security-scan",
                       "stayawake-security-report", "stayawake-security-alert",
                       "stayawake-security-remediate", "stayawake-security-audit"):
            self.assertIn(legacy, scripts, f"legacy script {legacy} must stay registered")
        self.assertEqual(scripts.get("saw"), "stayawake.cli:main")
        self.assertEqual(scripts.get("stayawake"), "stayawake.cli:main")


if __name__ == "__main__":
    unittest.main()
