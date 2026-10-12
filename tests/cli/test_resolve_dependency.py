#!/usr/bin/env python3
"""Tests for the known-malicious package prompt: only `yes` removes it, Enter keeps it, and the
package's own text is shown as safe text."""
from __future__ import annotations

import io
import os
import unittest
from unittest import mock

from stayawake.bots.security.pr.resolve import KEEP, TAKE_OUT, UNANSWERED, DependencyQuestion
from stayawake.cli.resolve.ask import ask_dependency
from stayawake.cli.resolve.build import build_resolver
from stayawake.cli.resolve.render import render_dependency

_QUESTION = DependencyQuestion("html-to-gutenberg", ("4.2.11",), ("package.json",))


def _ask(typed: str):
    return ask_dependency(_QUESTION, stdin=io.StringIO(typed), stderr=io.StringIO()).action


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class TestAskDependency(unittest.TestCase):
    def test_yes_removes_it(self):
        self.assertEqual(TAKE_OUT, _ask("yes\n"))
        self.assertEqual(TAKE_OUT, _ask("  YES \n"))

    def test_enter_and_no_keep_it(self):
        self.assertEqual(KEEP, _ask("\n"))
        self.assertEqual(KEEP, _ask("no\n"))

    def test_a_short_yes_is_asked_again(self):
        self.assertEqual(TAKE_OUT, _ask("y\nyes\n"))
        self.assertEqual(UNANSWERED, _ask("y\ny\ny\n"))

    def test_end_of_input_leaves_it_unanswered(self):
        self.assertEqual(UNANSWERED, _ask(""))


class TestRenderDependency(unittest.TestCase):
    def test_it_names_the_package_where_it_is_declared_and_what_removing_it_costs(self):
        text = render_dependency(_QUESTION)
        self.assertIn("html-to-gutenberg 4.2.11 is a known-malicious package", text)
        self.assertIn("package.json", text)
        self.assertIn("can break code that uses it", text)

    def test_a_long_list_of_files_is_shortened(self):
        many = tuple(f"app{n}/package.json" for n in range(5000))
        text = render_dependency(DependencyQuestion("evil", ("1",), many))
        self.assertIn("and 4995 more", text)
        self.assertLess(len(text), 2000)

    def test_a_package_name_cannot_drive_the_terminal(self):
        text = render_dependency(DependencyQuestion("evil\x1b[2Jpkg", ("1\x07",), ("a\rb/package.json",)))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("\r", text)


class TestTheResolverAsksAboutAPackage(unittest.TestCase):
    def test_a_dependency_question_reaches_the_dependency_prompt(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            resolver = build_resolver(_TTY("yes\n"), _TTY())
        self.assertEqual(TAKE_OUT, resolver(_QUESTION).action)


if __name__ == "__main__":
    unittest.main()
