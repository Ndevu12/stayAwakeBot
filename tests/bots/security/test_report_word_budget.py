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
# A finding that branches counts the UNION of its branches, so its number is above what any single
# render shows. That over-counts toward FLAGGING, which is the safe direction for a budget.
KNOWN_LONG = {
    "cached-github-keychain": (64, 88),
    "host-drop-artifact-weak": (57, 31),
    "persistence-surface-not-established": (37, 45),
    "grade.py:652": (45, 20),
    "self-hosted-runner-persistence": (35, 24),
    "os-service-persistence": (35, 21),
    "autorun-baseline-tampered": (39, 10),
    "grade.py:664": (36, 13),
    "ssh-authorized-keys-forced-command": (27, 22),
    "host-artifact-content-infected": (26, 22),
    "host-artifact-scanned-clean": (25, 23),
    "host-drop-artifacts": (17, 28),
    "git-config-fetch-exec": (21, 22),
}


def _words(text: str) -> int:
    return len(re.findall(r"\S+", text))


def _literals(node) -> str:
    return " ".join(n.value for n in ast.walk(node)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _literal(node, scope=None) -> str:
    """The literal text of a keyword value — following a NAME to where it was built.

    The wordiest finding in the tool assembles its detail into a list and appends to it before
    constructing the issue, so reading only the literals inside the `HygieneIssue(...)` call measured
    it as ZERO words. It was the one finding the budget most needed to see, and it was the one the
    budget could not see. Anything passed by name is now resolved against its enclosing function."""
    if scope is None:
        return _literals(node)
    # Any NAME the value mentions is resolved, so `detail`, `" ".join(detail)` and
    # `"x" + detail` are all seen. Own literals count too.
    parts = [_literals(node)]
    for name in {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}:
        parts.append(_resolve(name, scope))
    return " ".join(p for p in parts if p)


def _resolve(name: str, scope) -> str:
    parts = []
    for n in ast.walk(scope):
        if isinstance(n, ast.Assign) and any(getattr(t, "id", None) == name for t in n.targets):
            parts.append(_literals(n.value))
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr in ("append", "extend")
              and getattr(n.func.value, "id", None) == name):
            parts.append(" ".join(_literals(a) for a in n.args))
        elif isinstance(n, ast.AugAssign) and getattr(n.target, "id", None) == name:
            parts.append(_literals(n.value))
    return " ".join(p for p in parts if p)


def _findings():
    for path in sorted(_HYGIENE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        scopes = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "HygieneIssue":
                kw = {k.arg: k.value for k in node.keywords}
                if "id" not in kw:
                    continue
                enclosing = min((s for s in scopes
                                 if s.lineno <= node.lineno <= (s.end_lineno or s.lineno)),
                                key=lambda s: (s.end_lineno or s.lineno) - s.lineno, default=None)
                where = f"{path.name}:{node.lineno}"
                yield (_literal(kw["id"], enclosing) or where, where,
                       _words(_literal(kw["detail"], enclosing)) if "detail" in kw else 0,
                       _words(_literal(kw["remediation"], enclosing)) if "remediation" in kw else 0)


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

    def test_no_finding_measures_as_empty(self):
        # The guard on the guard. A finding whose text is BUILT before the call used to measure zero
        # words and sail past every budget — which is exactly where the worst one was hiding.
        for issue_id, where, detail, fix in _findings():
            with self.subTest(finding=issue_id, at=where):
                self.assertGreater(detail + fix, 0, f"{issue_id} measured as empty — the extractor "
                                                    "cannot see how its text is assembled")

    def test_a_new_finding_must_meet_the_budget(self):
        # Guards the guard: the exception list is closed, so an id added later is held to the rule.
        self.assertEqual(len(KNOWN_LONG), 13, "KNOWN_LONG changed — it may shrink, never grow")


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
