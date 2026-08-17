#!/usr/bin/env python3
"""The scope note points at a page. That page has to name every gap, or the pointer is a lie.

The list used to print after every run; it moved to the docs because a paragraph of things saw did
not do is noise at the end of a clean audit. Moving it is only safe while the page really carries it
— an unnamed axis reads as coverage of that axis, which is the defect the note exists to remove.
"""
from __future__ import annotations

import pathlib
import unittest

_DOCS = pathlib.Path(__file__).resolve().parents[3] / "docs/CLI.md"
_ANCHOR = "### What `saw audit` does not scan"


class TestTheScopePageNamesEveryGap(unittest.TestCase):
    def setUp(self):
        text = _DOCS.read_text(encoding="utf-8")
        self.assertIn(_ANCHOR, text, "the section the scope note links to does not exist")
        start = text.index(_ANCHOR)
        self.section = text[start:text.index("\n### ", start + 1)]

    def test_every_axis_is_named(self):
        for gap in ("survivor temp dirs", "global npm prefix", "Docker", "mounted filesystems",
                    "organization", "Windows autorun", "Run keys", "Startup folder",
                    "Scheduled Tasks"):
            with self.subTest(gap=gap):
                self.assertIn(gap, self.section)

    def test_it_says_a_clean_audit_is_not_a_clean_bill_of_health(self):
        self.assertIn("not a clean bill of health", self.section)


if __name__ == "__main__":
    unittest.main()
