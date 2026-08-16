#!/usr/bin/env python3
"""A finding is read by someone mid-incident. It gets a budget, and the budget is enforced.

The audience is a developer in the supply-chain path — they do not need the threat model restated
inside every finding. Measured before this budget existed: mean detail 34 words, worst 158, and
about a quarter of the corpus was sentences that only explained WHY.

The rule the budget encodes: every sentence is either WHAT WAS FOUND (location and state) or WHAT TO
DO (an imperative). Rationale belongs in the docs, behind `reference`. A word count cannot decide
which sentence is which — that stays a review obligation — but it can stop the corpus drifting back.

KNOWN_LONG is a ratchet, not an exemption: every entry is a finding that predates the budget and is
still above it. Entries come off as they are rewritten; nothing new may be added without shrinking
something else. A NEW finding must meet the budget outright.
"""
from __future__ import annotations

import ast
import pathlib
import re
import unittest

MAX_DETAIL_WORDS = 30
MAX_REMEDIATION_WORDS = 20

_HYGIENE = pathlib.Path(__file__).resolve().parents[3] / "src/stayawake/bots/security/hygiene"

# id -> (detail, remediation) word counts as measured when the budget landed. Shrink these.
KNOWN_LONG = {
    "persistence-surface-not-established": (36, 45),
    "host-drop-artifact-weak": (27, 31),
    "self-hosted-runner-persistence": (27, 24),
    "autorun-baseline-tampered": (39, 10),
    "ssh-authorized-keys-forced-command": (27, 22),
    "host-artifact-content-infected": (26, 22),
    "host-artifact-scanned-clean": (25, 23),
    "": (34, 13),
    "host-drop-artifacts": (17, 28),
    "git-config-fetch-exec": (21, 22),
    "os-service-persistence": (21, 21),
}


def _words(text: str) -> int:
    return len(re.findall(r"\S+", text))


def _literal(node) -> str:
    """The literal text of a keyword value — concatenations and f-string literals, placeholders
    excluded. A floor, which is the honest direction for a budget."""
    return " ".join(n.value for n in ast.walk(node)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _findings():
    for path in sorted(_HYGIENE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "HygieneIssue":
                kw = {k.arg: k.value for k in node.keywords}
                if "id" not in kw:
                    continue
                yield (_literal(kw["id"]), f"{path.name}:{node.lineno}",
                       _words(_literal(kw["detail"])) if "detail" in kw else 0,
                       _words(_literal(kw["remediation"])) if "remediation" in kw else 0)


class TestEveryFindingFitsTheBudget(unittest.TestCase):
    def test_no_finding_exceeds_it_unless_it_is_a_known_ratchet_entry(self):
        for issue_id, where, detail, fix in _findings():
            allowed_d, allowed_r = KNOWN_LONG.get(issue_id, (MAX_DETAIL_WORDS, MAX_REMEDIATION_WORDS))
            with self.subTest(finding=issue_id, at=where):
                self.assertLessEqual(detail, max(allowed_d, MAX_DETAIL_WORDS),
                                     f"{issue_id} detail grew to {detail} words")
                self.assertLessEqual(fix, max(allowed_r, MAX_REMEDIATION_WORDS),
                                     f"{issue_id} remediation grew to {fix} words")

    def test_the_ratchet_only_tightens(self):
        # An id that has been rewritten under budget must be REMOVED from KNOWN_LONG, so the list
        # always names real remaining work rather than quietly keeping stale headroom.
        measured = {i: (d, r) for i, _w, d, r in _findings()}
        for issue_id, (allowed_d, allowed_r) in KNOWN_LONG.items():
            with self.subTest(finding=issue_id):
                self.assertIn(issue_id, measured, f"{issue_id} no longer exists — drop it")
                detail, fix = measured[issue_id]
                self.assertFalse(detail <= MAX_DETAIL_WORDS and fix <= MAX_REMEDIATION_WORDS,
                                 f"{issue_id} now fits the budget — remove it from KNOWN_LONG")
                self.assertLessEqual(detail, allowed_d, f"{issue_id} detail grew")
                self.assertLessEqual(fix, allowed_r, f"{issue_id} remediation grew")

    def test_a_new_finding_must_meet_the_budget(self):
        # Guards the guard: the exception list is closed, so an id added later is held to the rule.
        self.assertEqual(len(KNOWN_LONG), 11, "KNOWN_LONG changed — it may shrink, never grow")


class TestTheSafetyWarningIsAtEveryDecisionPoint(unittest.TestCase):
    """Shortening must not thin the warning out. It is short now; it is still everywhere."""

    def test_the_wiper_note_still_reaches_every_rotation_site(self):
        sites = [p for p in _HYGIENE.rglob("*.py")
                 if "_WIPER_NOTE" in p.read_text(encoding="utf-8")]
        self.assertGreaterEqual(len(sites), 5, "the warning lost a file it used to appear in")

    def test_it_still_states_trigger_and_consequence(self):
        from stayawake.bots.security.hygiene.models import _WIPER_NOTE
        lowered = _WIPER_NOTE.lower()
        self.assertIn("rotat", lowered)          # the trigger
        self.assertIn("home directory", lowered)  # the consequence
        self.assertIn("reported", lowered)        # still hedged, never asserted
        self.assertLessEqual(_words(_WIPER_NOTE), 12)


if __name__ == "__main__":
    unittest.main()
