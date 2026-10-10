#!/usr/bin/env python3
"""Guards for the docs site's short links, written by .github/scripts/short_links.py.

saw prints these links, so each must open saw's own documentation and nothing else, and a page that
moves must not leave one leading nowhere. The script runs only in the docs workflow; its rules are
pinned here.
"""
from __future__ import annotations

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / ".github" / "scripts" / "short_links.py"
MAP = REPO / "docs" / "short-links.yml"

_spec = importlib.util.spec_from_file_location("short_links", SCRIPT)
sl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sl)


def _map_with(text: str) -> Path:
    folder = Path(tempfile.mkdtemp())
    (folder / "short-links.yml").write_text(text, encoding="utf-8")
    return folder / "short-links.yml"


class TestAShortLinkOnlyOpensThisSite(unittest.TestCase):
    def test_the_real_map_loads(self):
        self.assertIn("clean-audit", sl.load(MAP))

    def test_a_target_off_this_site_is_refused(self):
        for target in ("https://example.com/", "//example.com/", "/latest/how-to/",
                       "how-to/../../x/", "how-to//x/", "how-to/fix-findings",
                       "javascript:alert(1)/", "how-to/x/#a b", "How-To/x/", '"><script>/'):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    sl.load(_map_with(f"name: {target!r}\n"))

    def test_a_name_that_is_not_a_plain_word_is_refused(self):
        for name in ("Clean", "a/b", "../x", "-x", "a b", "1"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    sl.load(_map_with(f"{name!r}: how-to/x/\n" if name != "1" else "1: how-to/x/\n"))

    def test_an_empty_map_is_refused(self):
        for text in ("", "# nothing\n", "[]\n", "{}\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    sl.load(_map_with(text))


class TestTheRedirectPages(unittest.TestCase):
    def test_each_name_gets_a_page_that_opens_its_target_in_the_latest_docs(self):
        with tempfile.TemporaryDirectory() as root:
            written = sl.write({"clean-audit": "how-to/audit-a-machine/#what-a-clean-audit"}, Path(root))
            self.assertEqual(written, [Path(root) / "go" / "clean-audit" / "index.html"])
            page = written[0].read_text(encoding="utf-8")
            refresh = re.search(r'http-equiv="refresh" content="0; url=([^"]+)"', page)
            self.assertEqual(refresh.group(1), "/latest/how-to/audit-a-machine/#what-a-clean-audit")
            self.assertIn('href="/latest/how-to/audit-a-machine/#what-a-clean-audit"', page)
            self.assertIn('content="noindex"', page)

    def test_every_page_stays_under_go(self):
        with tempfile.TemporaryDirectory() as root:
            written = sl.write(sl.load(MAP), Path(root))
            self.assertEqual(len(written), len(sl.load(MAP)))
            for page in written:
                self.assertEqual(page.relative_to(root).parts[0], "go")


class TestTheBuildCheck(unittest.TestCase):
    def _built(self, root: Path, path: str, body: str) -> None:
        (root / path).mkdir(parents=True, exist_ok=True)
        (root / path / "index.html").write_text(body, encoding="utf-8")

    def test_a_link_to_a_page_and_section_that_exist_passes(self):
        with tempfile.TemporaryDirectory() as root:
            self._built(Path(root), "how-to/a", '<h3 id="part">Part</h3>')
            self.assertEqual(sl.missing({"a": "how-to/a/#part", "b": "how-to/a/"}, Path(root)), [])

    def test_a_missing_page_or_section_is_named(self):
        with tempfile.TemporaryDirectory() as root:
            self._built(Path(root), "how-to/a", '<h3 id="part">Part</h3>')
            problems = sl.missing({"gone": "how-to/b/", "moved": "how-to/a/#other"}, Path(root))
            self.assertEqual(problems, ["go/gone: no page at how-to/b/",
                                        "go/moved: how-to/a/ has no section #other"])

    def test_check_fails_the_run_when_a_link_leads_nowhere(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(sl.main(["short_links.py", "check", str(MAP), root]), 1)


if __name__ == "__main__":
    unittest.main()
