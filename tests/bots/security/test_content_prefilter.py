#!/usr/bin/env python3
"""PR1 (#1142): the ContentMatcher literal pre-filter must be a PURE optimization.

A signature's `prefilter` is a lowercase literal claimed to be present whenever its (IGNORECASE)
pattern matches; the matcher skips the regex when the literal is absent. A wrong prefilter (a literal
NOT actually implied by the pattern) would silently drop a true positive. This test forbids that by
proving the matcher's output is byte-identical with and without the prefilters, over real inputs that
exercise the signatures — so the ~9x speedup can never cost a detection.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from stayawake.bots.security.matchers.content import ContentMatcher
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions, Target

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _findings(target, sigs):
    return sorted((f.signature_id, f.path, f.line) for f in ContentMatcher().scan(target, sigs))


class TestContentPrefilter(unittest.TestCase):
    def _content_sigs(self):
        sigs = load_signatures(None).get("content", [])
        self.assertTrue(any(s.get("prefilter") for s in sigs),
                        "no content-signature prefilters present — nothing to guard")
        return sigs

    def test_prefilters_are_lowercase(self):
        # The check is `prefilter not in text.lower()`, so a non-lowercase literal could never match
        # and would wrongly skip every file.
        for s in self._content_sigs():
            pf = s.get("prefilter")
            if pf:
                self.assertEqual(pf, pf.lower(), f"{s['id']}: prefilter must be lowercase")

    def test_prefilter_is_verdict_identical(self):
        content = self._content_sigs()
        stripped = [{k: v for k, v in s.items() if k != "prefilter"} for s in content]
        for root in (FIXTURES, REPO):
            target = Target(root, str(root), ScanOptions())
            with_pf = _findings(target, content)
            without_pf = _findings(target, stripped)
            self.assertEqual(
                with_pf, without_pf,
                f"prefilter changed ContentMatcher output under {root} — a prefilter literal is not "
                f"implied by its pattern (skipped a real match).")
            self.assertTrue(without_pf,
                            f"corpus {root} exercised no content signature — the guard is vacuous.")


if __name__ == "__main__":
    unittest.main()
