#!/usr/bin/env python3
"""The scanner version the documentation tells people to pin is the newest release.

A release cuts its section in CHANGELOG.md, so a release that leaves an older version in a setup
example fails here, in the same pull request.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_RELEASED = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)
_PINNED = re.compile(r"^\s+version:\s*['\"]?(\d+\.\d+\.\d+)['\"]?\s*(#.*)?$", re.MULTILINE)


def _newest_release() -> str:
    """Read the newest released version from the changelog. Returns it."""
    found = _RELEASED.search((REPO / "CHANGELOG.md").read_text(encoding="utf-8"))
    assert found, "CHANGELOG.md names no released version"
    return found.group(1)


def _documented_versions() -> dict[str, list[str]]:
    """Collect every scanner version a setup example pins. Returns each page mapped to them."""
    pages = [REPO / "README.md", *sorted((REPO / "docs").rglob("*.md"))]
    out: dict[str, list[str]] = {}
    for page in pages:
        pinned = [found[0] for found in _PINNED.findall(page.read_text(encoding="utf-8"))]
        if pinned:
            out[str(page.relative_to(REPO))] = pinned
    return out


class TestDocumentedVersions(unittest.TestCase):
    def test_every_setup_example_pins_the_newest_release(self):
        newest = _newest_release()
        documented = _documented_versions()
        self.assertTrue(documented, "no setup example pins a scanner version")
        for page, versions in documented.items():
            with self.subTest(page=page):
                self.assertEqual(set(versions), {newest})


if __name__ == "__main__":
    unittest.main()
