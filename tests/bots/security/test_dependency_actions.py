#!/usr/bin/env python3
"""What saw tells an operator to do about a flagged dependency, on each surface that says it."""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake.bots.security.dependencies.remediation import REMOVE, UPGRADE, dependency_actions
from stayawake.bots.security.models import Finding, ScanResult, Severity
from stayawake.bots.security.pr.render import ACTION_LIMIT, dependency_action_lines, _pr_body
from stayawake.bots.security.service.report import _print_dependency_actions
from stayawake.bots.security.resolution import LocalTarget, REPOSITORY
from stayawake.bots.security.service import workers as scan_workers
from stayawake.bots.security.service.workers import WorkerScan
from stayawake.bots.security.sinks.render import render_markdown
from stayawake.bots.security import service


def _dep(name: str, *, action: str = REMOVE, advice: str | None = None,
         reference: str | None = None) -> Finding:
    return Finding(signature_id="malicious-dependency", category="supply-chain-dep",
                   severity=Severity.CRITICAL, path="package.json", description="d",
                   fix_advice=advice if advice is not None else f"do something about {name}",
                   dependency_action=action, reference=reference)


def _payload(findings=(), advisories=()) -> dict:
    result = ScanResult(target="acme/app", source="local", findings=list(findings),
                        advisories=list(advisories))
    return {"generated_at": "now", "results": [result.to_dict()],
            "summary": {"targets": 1, "infected": 0, "suspicious": 0, "residue": 0,
                        "findings": len(findings), "critical": 0, "high": 0}}


class TestTheTwoCasesStayApart(unittest.TestCase):
    """Check which heading a dependency lands under."""

    def test_a_package_with_a_patched_version_is_upgraded(self):
        body = "\n".join(dependency_action_lines(advisories=[_dep("lodash", action=UPGRADE)]))
        self.assertIn("**Upgrade**", body)
        self.assertNotIn("**Remove and replace**", body)

    def test_a_known_malicious_package_is_removed_and_replaced(self):
        body = "\n".join(dependency_action_lines(findings=[_dep("evil")]))
        self.assertIn("**Remove and replace**", body)
        self.assertNotIn("**Upgrade**", body)

    def test_both_appear_under_their_own_heading(self):
        body = "\n".join(dependency_action_lines(
            findings=[_dep("evil", advice="Remove evil")],
            advisories=[_dep("lodash", action=UPGRADE, advice="Upgrade lodash")]))
        self.assertLess(body.index("Remove evil"), body.index("Upgrade lodash"))
        self.assertIn("**Remove and replace**", body)
        self.assertIn("**Upgrade**", body)

    def test_an_advisory_with_no_patched_version_is_not_called_an_upgrade(self):
        """`vulnerability_fix` says remove when nothing is published to move to, so the heading must
        agree with the sentence under it."""
        from stayawake.bots.security.dependencies.remediation import vulnerability_fix
        self.assertEqual(REMOVE, vulnerability_fix("npm", "x", None).action)

    def test_an_external_auditors_advice_is_not_called_a_removal(self):
        """The external lane knows no fixed version but still says 'upgrade'."""
        from stayawake.bots.security.dependencies.remediation import external_advisory_fix
        self.assertEqual(UPGRADE, external_advisory_fix("x", "GHSA-1", "npm audit").action)


class TestItSaysEachThingOnce(unittest.TestCase):
    """Check what repeated findings for one package produce."""

    def test_the_same_advice_from_two_findings_is_said_once(self):
        same = "Remove evil-pkg now"
        body = "\n".join(dependency_action_lines(findings=[_dep("evil-pkg", advice=same),
                                                           _dep("evil-pkg", advice=same)]))
        self.assertEqual(1, body.count(same))

    def test_nothing_to_act_on_renders_nothing(self):
        self.assertEqual([], dependency_action_lines(findings=[], advisories=[]))

    def test_a_finding_without_advice_renders_nothing(self):
        bare = Finding(signature_id="x", category="c", severity=Severity.LOW, path="p",
                       description="d")
        self.assertEqual([], dependency_action_lines(findings=[bare]))

    def test_a_finding_that_names_no_action_renders_nothing(self):
        stray = Finding(signature_id="x", category="c", severity=Severity.LOW, path="p",
                        description="d", fix_advice="something")
        self.assertEqual([], dependency_action_lines(findings=[stray]))


class TestAHostilePackageCannotDriveTheReader(unittest.TestCase):
    """A package name reaches this text from a scanned lockfile, so the advice is attacker-shaped."""

    def test_markdown_cannot_be_broken_out_of(self):
        body = "\n".join(dependency_action_lines(
            findings=[_dep("x", advice="Remove `evil` [click](http://attacker.test)")]))
        self.assertNotIn("[click](http://attacker.test)</a>", body)
        self.assertNotIn("Remove `evil`", body)          # the span cannot be closed early
        self.assertIn("\u02bcevil\u02bc", body)

    def test_a_newline_cannot_forge_another_bullet(self):
        body = "\n".join(dependency_action_lines(
            findings=[_dep("x", advice="Remove a\n- Upgrade to attacker-pkg")]))
        self.assertEqual(1, len([ln for ln in body.splitlines() if ln.startswith("- ")]))


class TestTheListIsBounded(unittest.TestCase):
    """A hostile tree must not bloat a PR body with thousands of bullets."""

    def test_past_the_limit_the_rest_is_counted(self):
        many = [_dep(f"p{i}", advice=f"Remove p{i}") for i in range(ACTION_LIMIT + 10)]
        body = "\n".join(dependency_action_lines(findings=many))
        self.assertEqual(ACTION_LIMIT + 1, len([ln for ln in body.splitlines()
                                                if ln.startswith("- ")]))
        self.assertIn("and 10 more", body)


class TestItReachesThePullRequest(unittest.TestCase):
    """Check that the PR body carries it."""

    def test_the_body_carries_the_command(self):
        body = _pr_body("acme/app", [],
                        advisories=[_dep("lodash", action=UPGRADE,
                                         advice="Upgrade lodash to 4.17.21.  npm install lodash@4.17.21")])
        self.assertIn("npm install lodash@4.17.21", body)
        self.assertIn("Act on these before you merge", body)

    def test_the_body_carries_the_reference(self):
        body = _pr_body("acme/app", [],
                        findings=[_dep("evil", advice="Remove evil",
                                       reference="https://osv.dev/GHSA-xxxx")])
        self.assertIn("https://osv.dev/GHSA-xxxx", body)

    def test_a_body_with_nothing_to_act_on_has_no_heading(self):
        self.assertNotIn("Act on these", _pr_body("acme/app", []))


class TestItReachesTheReportFile(unittest.TestCase):
    """Check that `latest.md` carries it, at the top."""

    def test_the_report_carries_the_command(self):
        md = render_markdown(_payload(
            advisories=[_dep("lodash", action=UPGRADE,
                             advice="Upgrade lodash to 4.17.21.  npm install lodash@4.17.21")]))
        self.assertIn("npm install lodash@4.17.21", md)
        self.assertIn("Act on these dependencies", md)

    def test_it_sits_above_the_findings(self):
        md = render_markdown(_payload(findings=[_dep("evil", advice="Remove evil")]))
        self.assertLess(md.index("Act on these dependencies"), md.index("## Findings"))

    def test_a_report_with_nothing_to_act_on_has_no_heading(self):
        self.assertNotIn("Act on these", render_markdown(_payload()))


class TestItReachesTheTerminal(unittest.TestCase):
    """Check that the run's footer carries it."""

    def _run(self, findings=(), advisories=()) -> str:
        result = ScanResult(target="acme/app", source="local", findings=list(findings),
                            advisories=list(advisories))
        buf = io.StringIO()
        with redirect_stderr(buf):
            _print_dependency_actions([result])
        return buf.getvalue()

    def test_the_footer_carries_the_command(self):
        out = self._run(advisories=[_dep("lodash", action=UPGRADE,
                                         advice="Upgrade lodash to 4.17.21.  npm install lodash@4.17.21")])
        self.assertIn("npm install lodash@4.17.21", out)
        self.assertIn("Act on these dependencies", out)

    def test_both_headings_are_named(self):
        out = self._run(findings=[_dep("evil", advice="Remove evil")],
                        advisories=[_dep("lodash", action=UPGRADE, advice="Upgrade lodash")])
        self.assertIn("Remove and replace:", out)
        self.assertIn("Upgrade:", out)

    def test_a_run_with_nothing_to_act_on_prints_nothing(self):
        self.assertEqual("", self._run())

    def test_a_hostile_package_name_cannot_drive_the_terminal(self):
        out = self._run(findings=[_dep("x", advice="Remove \x1b[2Jevil\x07 now")])
        self.assertNotIn("\x1b[2J", out)
        self.assertNotIn("\x07", out)


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
        result.advisories.append(_dep("lodash", action=UPGRADE,
                                      advice="Upgrade lodash to 4.17.21.  npm install lodash@4.17.21"))
        out = self._scan(result)
        self.assertIn("npm install lodash@4.17.21", out)
        self.assertIn("Act on these dependencies", out)

    def test_a_scan_that_flags_nothing_prints_no_footer(self):
        self.assertNotIn("Act on these", self._scan(ScanResult(target="acme/app", source="local")))


if __name__ == "__main__":
    unittest.main()
