#!/usr/bin/env python3
"""What matters most is read first — on every surface that reports, not just the scan table.

The scan table has always sorted worst-first. The audit emitted findings in probe-registration
order, so what appeared at the top was whichever check happened to be listed first. The persisted
markdown bundle did not sort at all, so an infected repository could sit below a clean one in the
file kept as the record.

Both now answer the question the same way, from the tables that already define the ordering:
`TIER_IDS` for a host finding, `_verdict` for a scanned target.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security import hygiene
from stayawake.bots.security.hygiene.models import HygieneIssue, response_order
from stayawake.bots.security.sinks.render import render_markdown, render_terminal, report_order


def _issue(issue_id, severity="warning"):
    return HygieneIssue(id=issue_id, severity=severity, title=issue_id, detail="d", remediation="r")


def _result(target, *, infected=False, suspicious=False, total=0):
    return {"target": target, "source": "local", "infected": infected, "suspicious": suspicious,
            "error": None, "notes": [], "advisories": [],
            "summary": {"total": total, "max_severity": "critical" if total else None},
            "findings": [{"signature_id": "s", "severity": "critical", "confidence": "confirmed",
                          "path": "p", "line": 1, "description": "d", "evidence": "e"}] * total}


class TestAHostFindingIsRankedByItsTier(unittest.TestCase):
    def test_a_live_foothold_outranks_an_exposure_which_outranks_the_rest(self):
        self.assertLess(response_order("os-service-persistence"),
                        response_order("git-credentials-plaintext"))
        self.assertLess(response_order("git-credentials-plaintext"),
                        response_order("vscode-autoapprove-risky"))

    def test_it_reads_the_same_table_the_banner_does(self):
        # A second ranking would drift from `incident_tier()`; adding a tier must move both.
        from stayawake.bots.security.hygiene.models import TIER_IDS
        for rank, (_tier, ids) in enumerate(TIER_IDS):
            for issue_id in ids:
                with self.subTest(issue_id=issue_id):
                    self.assertEqual(response_order(issue_id), rank)

    def test_the_audit_emits_worst_first(self):
        report = hygiene.render([_issue("vscode-autoapprove-risky"),
                                 _issue("git-credentials-plaintext"),
                                 _issue("os-service-persistence")], color=False, width=100)
        positions = {name: report.index(name) for name in
                     ("os-service-persistence", "git-credentials-plaintext",
                      "vscode-autoapprove-risky")}
        self.assertLess(positions["os-service-persistence"],
                        positions["git-credentials-plaintext"])
        self.assertLess(positions["git-credentials-plaintext"],
                        positions["vscode-autoapprove-risky"])

    def test_ordering_is_deterministic_for_equal_ranks(self):
        # Two findings of the same tier must not swap between runs.
        same = [_issue("b-check"), _issue("a-check")]
        first = hygiene.render(same, color=False, width=100)
        self.assertLess(first.index("a-check"), first.index("b-check"))

    def test_warnings_still_precede_review_items(self):
        report = hygiene.render([_issue("os-service-persistence", "info"),
                                 _issue("git-credentials-plaintext", "warning")],
                                color=False, width=100)
        self.assertLess(report.index("git-credentials-plaintext"),
                        report.index("os-service-persistence"))


class TestThePersistedBundleIsOrderedToo(unittest.TestCase):
    PAYLOAD = {"summary": {"targets": 3, "infected": 1, "suspicious": 1, "findings": 3,
                           "critical": 1, "high": 0},
               "generated_at": "t",
               "results": [_result("clean-repo"),
                           _result("infected-repo", infected=True, total=2),
                           _result("suspect-repo", suspicious=True, total=1)]}

    def test_markdown_lists_infected_before_suspect_before_clean(self):
        out = render_markdown(self.PAYLOAD)
        self.assertLess(out.index("infected-repo"), out.index("suspect-repo"))
        self.assertLess(out.index("suspect-repo"), out.index("clean-repo"))

    def test_clean_targets_are_still_listed(self):
        # The bundle is a RECORD — every target belongs in it. Ordering is the change, not scope.
        self.assertIn("clean-repo", render_markdown(self.PAYLOAD))

    def test_both_renderers_use_one_ordering(self):
        results = self.PAYLOAD["results"]
        ordered = [r["target"] for r in sorted(results, key=report_order)]
        terminal = render_terminal(self.PAYLOAD, color=False)
        self.assertEqual(ordered, ["infected-repo", "suspect-repo", "clean-repo"])
        self.assertLess(terminal.index("infected-repo"), terminal.index("clean-repo"))


if __name__ == "__main__":
    unittest.main()
