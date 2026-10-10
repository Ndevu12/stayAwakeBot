#!/usr/bin/env python3
"""The documentation domain is written once, in mkdocs.yml.

Everything that can read it does. `pyproject.toml`, the README and `stayawake.utils.docs_site` (an
installed saw has no mkdocs.yml to read) cannot, so they hold a literal — and this pins that literal
to the one source, which is what stops the copies drifting apart the way they did when the site
moved subdomain. Every link saw prints is a short link the site serves, and every link leads to a
page and section that exist in `docs/`.
"""
from __future__ import annotations

import pathlib
import re
import unicodedata
import unittest

import yaml

from stayawake.utils import docs_site

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_MKDOCS = _ROOT / "mkdocs.yml"
_PYPROJECT = _ROOT / "pyproject.toml"
_README = _ROOT / "README.md"
_WORKFLOW = _ROOT / ".github/workflows/docs.yml"
_SUPPORT = _ROOT / "SUPPORT.md"
_DOCS = _ROOT / "docs"
_SRC = _ROOT / "src/stayawake"
_SHORT_LINKS = _DOCS / "short-links.yml"


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


def _section_ids(page: pathlib.Path) -> set[str]:
    """The ids the site gives a page's headings: an explicit `{#id}`, else the heading slugified as
    Python-Markdown's toc does."""
    ids = set()
    for line in page.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"#{1,6}\s+(.*)", line)
        if not heading:
            continue
        explicit = re.search(r"\{#([\w-]+)\}", heading.group(1))
        if explicit:
            ids.add(explicit.group(1))
            continue
        text = unicodedata.normalize("NFKD", heading.group(1)).encode("ascii", "ignore").decode()
        text = re.sub(r"[^\w\s-]", "", text).strip().lower()
        ids.add(re.sub(r"[-\s]+", "-", text))
    return ids


def _source_page(site_path: str) -> tuple[pathlib.Path | None, str]:
    """Map a path on the latest documentation to the page in docs/ it is built from. Returns the
    page, or None, and the section id it names."""
    rest, _, section = site_path.partition("#")
    path = rest.strip("/")
    candidates = [_DOCS / f"{path}.md", _DOCS / path / "index.md"] if path else [_DOCS / "index.md"]
    return next((c for c in candidates if c.is_file()), None), section


def _short_links() -> dict[str, str]:
    return yaml.safe_load(_SHORT_LINKS.read_text(encoding="utf-8"))


def _names_saw_prints() -> list[str]:
    prefix = docs_site.SITE + "/go/"
    return [v[len(prefix):].strip("/") for v in vars(docs_site).values()
            if isinstance(v, str) and v.startswith(prefix)]


def _pages_readers_are_sent_to() -> list[str]:
    """Every path on the latest documentation that a short link or the README and support guide
    lead to."""
    latest = docs_site.SITE + "/latest/"
    found = list(_short_links().values())
    for doc in (_README, _SUPPORT):
        found += re.findall(r"\(" + re.escape(latest) + r"([^)\s]*)\)", doc.read_text(encoding="utf-8"))
    return found


class TestEveryDocsLinkLeadsToAPage(unittest.TestCase):
    def test_saw_links_the_site_mkdocs_publishes(self):
        self.assertEqual(docs_site.SITE, _declared_site_url().rstrip("/"))

    def test_every_link_saw_prints_is_a_short_link_the_site_serves(self):
        names = _names_saw_prints()
        self.assertGreaterEqual(len(names), 4, "the links saw prints were not found")
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, _short_links(), f"saw prints go/{name}/ but the site has no such link")

    def test_no_other_source_file_writes_a_docs_address(self):
        """One home: a topic's address is built in docs_site and nowhere else."""
        host = _declared_site_url().split("://", 1)[1].rstrip("/")
        for path in sorted(_SRC.rglob("*.py")):
            if path.name == "docs_site.py":
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(_ROOT)):
                self.assertNotIn(host, text)
                self.assertNotIn("/blob/main/docs/", text)

    def test_readers_are_not_sent_to_a_path_inside_the_repository(self):
        """The README is also the package page, where a relative docs/ link leads nowhere."""
        for doc in (_README, _SUPPORT):
            with self.subTest(doc=doc.name):
                self.assertNotRegex(doc.read_text(encoding="utf-8"), r"\]\((?:\./)?docs/")

    def test_every_link_names_a_page_and_section_that_exist(self):
        paths = _pages_readers_are_sent_to()
        self.assertGreaterEqual(len(paths), 25, "the links were not found, so none were checked")
        for site_path in paths:
            with self.subTest(path=site_path):
                page, section = _source_page(site_path)
                self.assertIsNotNone(page, f"{site_path} has no page in docs/")
                if section:
                    self.assertIn(section, _section_ids(page), f"{site_path} names a section {page.name} lacks")

if __name__ == "__main__":
    unittest.main()
