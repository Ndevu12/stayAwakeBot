#!/usr/bin/env python3
"""Operator documentation describes the verdict, never process status."""
from __future__ import annotations

import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SURFACES = [_ROOT / "docs", _ROOT / "README.md", _ROOT / "SUPPORT.md"]
_FORBIDDEN = re.compile(
    r"exit code|exit-codes|exits `|echo \$\?|\| Exit \|",
    re.I,
)


def _pages():
    for surface in _SURFACES:
        if surface.is_file():
            yield surface
            continue
        yield from surface.rglob("*.md")


class TestOperatorDocsOmitExitCodes(unittest.TestCase):
    def test_there_is_no_exit_codes_page(self):
        self.assertFalse((_ROOT / "docs/reference/exit-codes.md").exists())

    def test_pages_do_not_mention_process_status(self):
        hits = []
        for page in _pages():
            text = page.read_text(encoding="utf-8")
            if _FORBIDDEN.search(text):
                hits.append(str(page.relative_to(_ROOT)))
        self.assertEqual(hits, [], "operator docs mentioned process status")


if __name__ == "__main__":
    unittest.main()
