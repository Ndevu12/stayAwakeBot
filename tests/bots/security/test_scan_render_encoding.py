#!/usr/bin/env python3
"""The scan report must not carry attacker-chosen control text to the terminal.

`fix_advice` and `reference` were encoded; `evidence` and `path` were interpolated raw two lines
above them. Both are attacker-chosen — evidence is file bytes, and whoever writes the repository
names the file — so a crafted repo could retitle the terminal, clear the screen, or emit text a CI
system reads as its own instructions, from a scan of that repo.

Each surface takes its own threat's encoder: the terminal is a CI log, so it defangs the workflow
introducers; the markdown bundle is a rendered file, so it defangs Markdown.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security.sinks.render import render_terminal, render_markdown

HOSTILE = ("x\x1b]0;pwned\x07::error::FAKE-saw-says-clean\x1b[2J"
           "##[error]also-this‮gnitcefni")


def _payload(**overrides):
    finding = {"signature_id": "sig", "severity": "critical", "confidence": "confirmed",
               "path": "pkg/index.js", "line": 1, "description": "d", "evidence": "e",
               "fix_advice": "f", "reference": "https://example.test"}
    finding.update(overrides)
    return {"summary": {"targets": 1, "infected": 1, "suspicious": 0, "findings": 1,
                        "critical": 1, "high": 0},
            "generated_at": "t",
            "results": [{"target": "repo", "source": "local", "infected": True,
                         "suspicious": False, "error": None, "notes": [], "advisories": [],
                         "summary": {"total": 1, "max_severity": "critical"},
                         "findings": [finding]}]}


class TestTheTerminalNeverCarriesControlText(unittest.TestCase):
    def _rendered(self, **overrides):
        return render_terminal(_payload(**overrides), color=False)

    def test_evidence_is_defanged(self):
        out = self._rendered(evidence=HOSTILE)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)

    def test_a_crafted_path_is_defanged(self):
        # The path is chosen by whoever writes the repository, not by us.
        out = self._rendered(path="pkg/" + HOSTILE)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)

    def test_ci_workflow_introducers_are_defanged_in_both_fields(self):
        for field in ("evidence", "path"):
            with self.subTest(field=field):
                out = self._rendered(**{field: HOSTILE})
                self.assertNotIn("::error::", out)
                self.assertNotIn("##[", out)

    def test_the_finding_still_renders(self):
        # Defanging must not silence the report — an encoder that drops the line is worse.
        out = self._rendered(evidence=HOSTILE)
        self.assertIn("sig", out)
        self.assertIn("pkg/index.js", out)

    def test_an_ordinary_finding_is_unchanged(self):
        out = self._rendered(evidence="const x = 1;")
        self.assertIn("const x = 1;", out)
        self.assertIn("pkg/index.js:1", out)


class TestTheMarkdownBundleDefangsMarkdown(unittest.TestCase):
    """`latest.md` is a rendered file, not a CI log — its threat is markup injection, so it takes
    `sanitize`/`code` rather than the terminal's encoder."""

    def test_a_crafted_path_cannot_break_out(self):
        out = render_markdown(_payload(path="pkg/" + HOSTILE))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)

    def test_evidence_stays_inside_its_code_span(self):
        out = render_markdown(_payload(evidence="a` broken ` span"))
        self.assertNotIn("a` broken ` span", out)

    def test_an_ordinary_finding_is_unchanged(self):
        out = render_markdown(_payload())
        self.assertIn("pkg/index.js:1", out)


if __name__ == "__main__":
    unittest.main()
