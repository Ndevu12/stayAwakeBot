#!/usr/bin/env python3
"""What a pull request tells an operator to do about a flagged dependency."""
from __future__ import annotations

import unittest

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.pr.render import dependency_actions, _pr_body


def _dep(name: str, *, fixed: str | None = None, advice: str | None = None,
         reference: str | None = None) -> Finding:
    return Finding(signature_id="malicious-dependency", category="supply-chain-dep",
                   severity=Severity.CRITICAL, path="package.json", description="d",
                   fix_advice=advice if advice is not None else f"do something about {name}",
                   fixed_version=fixed, reference=reference)


class TestTheTwoCasesStayApart(unittest.TestCase):
    """Check which heading a dependency lands under."""

    def test_a_package_with_a_patched_version_is_upgraded(self):
        lines = dependency_actions(advisories=[_dep("lodash", fixed="4.17.21", advice="Upgrade lodash")])
        body = "\n".join(lines)
        self.assertIn("**Upgrade**", body)
        self.assertNotIn("**Remove and replace**", body)

    def test_a_package_with_no_patched_version_is_replaced(self):
        lines = dependency_actions(findings=[_dep("evil", advice="Remove evil")])
        body = "\n".join(lines)
        self.assertIn("**Remove and replace**", body)
        self.assertNotIn("**Upgrade**", body)

    def test_both_appear_under_their_own_heading(self):
        body = "\n".join(dependency_actions(
            findings=[_dep("evil", advice="Remove evil")],
            advisories=[_dep("lodash", fixed="4.17.21", advice="Upgrade lodash")]))
        self.assertLess(body.index("Remove evil"), body.index("Upgrade lodash"))
        self.assertIn("**Remove and replace**", body)
        self.assertIn("**Upgrade**", body)


class TestItSaysEachThingOnce(unittest.TestCase):
    """Check what repeated findings for one package produce."""

    def test_the_same_advice_from_two_findings_is_said_once(self):
        same = "Remove evil-pkg now"
        body = "\n".join(dependency_actions(findings=[_dep("evil-pkg", advice=same),
                                                      _dep("evil-pkg", advice=same)]))
        self.assertEqual(1, body.count(same))

    def test_nothing_to_act_on_renders_nothing(self):
        self.assertEqual([], dependency_actions(findings=[], advisories=[]))

    def test_a_finding_without_advice_renders_nothing(self):
        bare = Finding(signature_id="x", category="c", severity=Severity.LOW, path="p",
                       description="d")
        self.assertEqual([], dependency_actions(findings=[bare]))


class TestItReachesThePullRequest(unittest.TestCase):
    """Check that the body carries it."""

    def test_the_body_carries_the_command(self):
        body = _pr_body("acme/app", [],
                        advisories=[_dep("lodash", fixed="4.17.21",
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


if __name__ == "__main__":
    unittest.main()
