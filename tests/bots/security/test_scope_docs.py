#!/usr/bin/env python3
"""The scope note points at a page. That page has to bound what a clean result means.

It used to enumerate every surface examined and every one skipped. That list is a map of where to
hide, and it is worth less to an operator than the bound is: what a clean result covers, and what it
does not. So the page states the consequence, and this pins the consequence rather than the map.
"""
from __future__ import annotations

import pathlib
import unittest

_DOCS = pathlib.Path(__file__).resolve().parents[3] / "docs/how-to/audit-a-machine.md"
_ANCHOR = "### What a clean audit does and does not mean"


class TestTheScopePageNamesEveryGap(unittest.TestCase):
    def setUp(self):
        text = _DOCS.read_text(encoding="utf-8")
        self.assertIn(_ANCHOR, text, "the section the scope note links to does not exist")
        start = text.index(_ANCHOR)
        # The section may be the last on the page, so a following "### " is not guaranteed;
        # slice to end-of-file when there is none rather than raising.
        nxt = text.find("\n### ", start + 1)
        self.section = text[start:nxt if nxt != -1 else len(text)]

    def test_it_bounds_what_a_clean_result_covers(self):
        for bound in ("this machine", "at this moment", "not your images",
                      "not the accounts", "publisher released"):
            with self.subTest(bound=bound):
                self.assertIn(bound, self.section)

    def test_it_says_an_unrun_check_is_not_a_clean_one(self):
        self.assertIn("could not run", self.section)
        self.assertIn("rotation as unsafe", self.section)

    def test_it_does_not_publish_where_the_tool_looks(self):
        # A list of the paths examined, and of the ones skipped, is a map of where to hide. An
        # operator acts on the bound; only someone tuning against the tool needs the locations.
        for location in ("/tmp", "$TMPDIR", "npm prefix", "Run keys", "Startup folder",
                         "Scheduled Tasks", "LaunchAgents", "systemd", "node_modules"):
            with self.subTest(location=location):
                self.assertNotIn(location, self.section)

    def test_it_says_a_clean_audit_is_not_a_clean_bill_of_health(self):
        self.assertIn("not a clean bill of health", self.section)


if __name__ == "__main__":
    unittest.main()
