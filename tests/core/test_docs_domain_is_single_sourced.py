#!/usr/bin/env python3
"""The documentation domain is written once, in mkdocs.yml.

Everything that can read it does. `pyproject.toml` and the README are static formats that cannot,
so they hold a literal — and this pins that literal to the one source, which is what stops the
copies drifting apart the way they did when the site moved subdomain.
"""
from __future__ import annotations

import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_MKDOCS = _ROOT / "mkdocs.yml"
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_WORKFLOW = _ROOT / ".github/workflows/docs.yml"


def _declared_site_url() -> str:
    """The one declaration, read without importing mkdocs (`!ENV` is not plain YAML)."""
    text = _MKDOCS.read_text(encoding="utf-8")
    m = re.search(r'^site_url:\s*(?:!ENV\s*\[\s*\w+\s*,\s*)?["\']([^"\']+)["\']', text, re.M)
    assert m, "mkdocs.yml has no readable site_url"
    return m.group(1)


class TestTheDomainIsWrittenOnce(unittest.TestCase):
    def setUp(self):
        self.site_url = _declared_site_url()
        self.host = self.site_url.split("://", 1)[1].rstrip("/")

    def test_pyproject_documentation_url_matches(self):
        m = re.search(r'^Documentation\s*=\s*"([^"]+)"', _PYPROJECT.read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(m, "pyproject.toml declares no Documentation URL")
        self.assertIn(self.host, m.group(1),
                      "pyproject.toml's Documentation URL does not use the domain mkdocs.yml declares")

    def test_readme_points_at_the_same_host(self):
        readme = _README.read_text(encoding="utf-8")
        self.assertIn(self.host, readme,
                      "the README does not link the domain mkdocs.yml declares")

    def test_no_other_host_is_advertised_as_the_docs_site(self):
        """A stale subdomain left in either file is the failure this test exists to catch."""
        stale = re.findall(r'https://([a-z0-9.-]*ndevuspace\.com)', _README.read_text(encoding="utf-8")
                           + _PYPROJECT.read_text(encoding="utf-8"))
        for found in stale:
            self.assertEqual(found, self.host,
                             f"{found} is advertised but mkdocs.yml declares {self.host}")

    def test_the_workflow_does_not_hardcode_it(self):
        """The deploy derives the host from mkdocs.yml; a literal there is a second source."""
        self.assertNotIn(self.host, _WORKFLOW.read_text(encoding="utf-8"),
                         "the docs workflow hardcodes the domain instead of reading mkdocs.yml")


if __name__ == "__main__":
    unittest.main()
