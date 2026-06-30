#!/usr/bin/env python3
"""Tests for the unified `saw` dispatcher (stayawake.cli).

These verify pure ROUTING — that each verb maps to the right service call with the
right arguments — plus the guards the redesign promised:
  * no subcommand/alias name collisions (so a future verb can't silently shadow one),
  * legacy flag spellings (--local-only / --open-pr) still parse,
  * the `saw sec <verb>` namespace seam is a transparent no-op today,
  * pyproject ships saw/stayawake + the health scripts, and NO legacy security scripts.
The real scanning/remediation functions are mocked; we assert how they are called.
"""
from __future__ import annotations

import argparse
import io
import pathlib
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
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
        rc = cli.main(["scan", "-r", "-c", "cfg.yml", "./repo", "-p", "extra",
                       "--json", "--sarif", "out.sarif", "-d", "rep", "--alert"])
        self.assertEqual(rc, 0)
        # config_path is the one positional; everything else is keyword-only now.
        (config_path,) = m.call_args.args
        kw = m.call_args.kwargs
        self.assertEqual(config_path, "cfg.yml")
        self.assertTrue(kw["remote"])
        self.assertTrue(kw["json_out"])
        self.assertEqual(kw["sarif_path"], "out.sarif")
        self.assertEqual(kw["reports_dir"], "rep")
        self.assertTrue(kw["alert"])
        self.assertIn("./repo", kw["paths"])
        self.assertIn("extra", kw["paths"])

    @mock.patch("stayawake.bots.security.service.scan", return_value=0)
    def test_scan_defaults_to_local(self, m):
        cli.main(["scan"])
        self.assertFalse(m.call_args.kwargs["remote"])

    @mock.patch("stayawake.bots.security.service.scan", return_value=0)
    def test_bare_scan_passes_no_paths(self, m):
        cli.main(["scan"])
        self.assertIsNone(m.call_args.kwargs["paths"])

    @mock.patch("stayawake.bots.security.service.scan", return_value=0)
    def test_short_alias_routes_to_scan(self, m):
        cli.main(["s", "-r"])
        self.assertTrue(m.call_args.kwargs["remote"])

    def test_scan_is_read_only_no_remediation_or_legacy_flags(self):
        # The redesign removed --fix/--apply/--pr (remediation → `saw fix`) and the
        # --local/--fail flags (local is the default; the verdict IS the exit code).
        for flag in ("--fix", "--apply", "--pr", "--local", "--local-only", "-f"):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                cli.main(["scan", flag])


class TestSecNamespace(unittest.TestCase):
    @mock.patch("stayawake.bots.security.service.scan", return_value=0)
    def test_leading_sec_token_is_stripped(self, m):
        cli.main(["sec", "scan", "-r"])
        self.assertTrue(m.call_args.kwargs["remote"])


class TestFix(unittest.TestCase):
    @mock.patch("stayawake.bots.security.remediator.fix", return_value=0)
    def test_fix_routes_to_remediator_fix(self, m):
        rc = cli.main(["fix"])
        self.assertEqual(rc, 0)
        (config_path,) = m.call_args.args
        kw = m.call_args.kwargs
        self.assertIsNone(config_path)
        self.assertFalse(kw["remote"])      # local by default
        self.assertIsNone(kw["paths"])
        self.assertFalse(kw["no_stream"])

    @mock.patch("stayawake.bots.security.remediator.fix", return_value=0)
    def test_remote_scope(self, m):
        cli.main(["fix", "--remote"])
        self.assertTrue(m.call_args.kwargs["remote"])

    @mock.patch("stayawake.bots.security.remediator.fix", return_value=0)
    def test_paths_route_through(self, m):
        cli.main(["fix", "./repo", "-p", "extra"])
        paths = m.call_args.kwargs["paths"]
        self.assertIn("./repo", paths)
        self.assertIn("extra", paths)

    def test_fix_has_no_apply_or_pr_flags(self):
        # Cleanup is always a PR (the review gate) — there is no apply/preview/--pr to stack.
        for flag in ("--apply", "--pr", "--open-pr"):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                cli.main(["fix", flag])

    @mock.patch("stayawake.bots.security.remediator.fix", return_value=2)
    def test_missing_explicit_config_exits_nonzero(self, _):
        # #1054: a missing --config is a clean exit-2, not a crash; fix propagates it.
        self.assertEqual(cli.main(["fix", "--config", "nope.yml"]), 2)

    @mock.patch("stayawake.bots.security.remediator.fix", return_value=1)
    def test_needs_review_propagates_exit_one(self, _):
        # A repo that couldn't be auto-cleaned makes fix exit 1 (a CI signal).
        self.assertEqual(cli.main(["fix"]), 1)


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
        # The health bot is still driven by its console scripts (remote-only).
        for health in ("stayawake-health-check", "stayawake-health-report",
                       "stayawake-health-alert"):
            self.assertIn(health, scripts, f"health script {health} must stay registered")
        self.assertEqual(scripts.get("saw"), "stayawake.cli:main")
        self.assertEqual(scripts.get("stayawake"), "stayawake.cli:main")
        # The legacy security scripts are REMOVED — `saw` is the only security entry point.
        for legacy in ("stayawake-security-scan", "stayawake-security-report",
                       "stayawake-security-alert", "stayawake-security-remediate",
                       "stayawake-security-audit"):
            self.assertNotIn(legacy, scripts, f"legacy security script {legacy} must be gone")


if __name__ == "__main__":
    unittest.main()
