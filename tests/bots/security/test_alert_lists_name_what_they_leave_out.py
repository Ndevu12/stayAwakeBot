#!/usr/bin/env python3
"""An issue or pull request that lists findings shows the confirmed ones first and says how many more
there are; no finding drops out of a list without a word."""
from __future__ import annotations

import unittest

from stayawake.bots.security import alerter
from stayawake.bots.security.models import CONFIRMED, HEURISTIC, Finding, Severity
from stayawake.bots.security.pr import render


def _finding(path: str, confidence: str) -> Finding:
    severity = Severity.CRITICAL if confidence == CONFIRMED else Severity.MEDIUM
    return Finding(signature_id=f"sig-{path}", category="c", severity=severity, path=path,
                   description="d", confidence=confidence)


class TestTheIssueSawOpensForAnInfectedRepository(unittest.TestCase):
    def test_it_lists_the_confirmed_findings_and_says_how_many_more_there_are(self):
        findings = ([_finding(f"maybe/{i}.js", HEURISTIC).to_dict() for i in range(25)]
                    + [_finding(f"payload/{i}.js", CONFIRMED).to_dict() for i in range(5)])
        body = alerter._issue_body({"target": "acme/app", "source": "remote", "findings": findings,
                                    "summary": {"total": 30, "max_severity": "critical"}})
        for i in range(5):
            self.assertIn(f"payload/{i}.js", body)
        self.assertIn("…and 5 more", body)


class TestTheIssueSawOpensWhenItCannotOpenAFix(unittest.TestCase):
    def test_it_lists_the_confirmed_findings_and_says_how_many_more_there_are(self):
        findings = ([_finding(f"maybe/{i}.js", HEURISTIC) for i in range(50)]
                    + [_finding(f"payload/{i}.js", CONFIRMED) for i in range(5)])
        body = render._issue_body("acme/app", findings)
        for i in range(5):
            self.assertIn(f"payload/{i}.js", body)
        self.assertIn("…and 5 more", body)


class TestTheFixPullRequestsListToReview(unittest.TestCase):
    def test_it_says_how_many_more_need_review(self):
        suspicious = [_finding(f"maybe/{i}.js", HEURISTIC) for i in range(55)]
        body = render._pr_body("acme/app", [], suspicious=suspicious)
        self.assertIn("…and 5 more", body)


if __name__ == "__main__":
    unittest.main()
