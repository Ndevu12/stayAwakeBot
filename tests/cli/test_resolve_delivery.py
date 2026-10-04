#!/usr/bin/env python3
"""The question `saw fix amend` puts about the files one delivery commit added, and how the answer
is read."""
from __future__ import annotations

import io
import unittest
from unittest import mock

from stayawake.bots.security.pr.resolve import (KEEP, TAKE_OUT, UNANSWERED, ArrivedFile,
                                                DeliveryQuestion)
from stayawake.cli.resolve.ask import ask_delivery
from stayawake.cli.resolve.build import build_resolver
from stayawake.cli.resolve.render import render_delivery

FILES = ("public/fonts/a.woff2", "public/fonts/b.woff2", ".vscode/launch.json", ".gitignore-extra")


def _question(paths=FILES, **kw):
    base = dict(commit="1a2b3c4d5e6f" + "0" * 28, date="2026-09-03T10:00:00+02:00",
                subject="add build tooling", removing=("public/fonts/text.woff",),
                files=tuple(ArrivedFile(p, str(n) * 40) for n, p in enumerate(paths, 1)))
    base.update(kw)
    return DeliveryQuestion(**base)


def _ask(question, *answers):
    stderr = io.StringIO()
    answer = ask_delivery(question, stdin=io.StringIO("".join(a + "\n" for a in answers)),
                          stderr=stderr)
    return answer, stderr.getvalue()


class TestTheQuestionShows(unittest.TestCase):

    def test_the_commit_as_it_states_itself_and_what_saw_removes(self):
        out = render_delivery(_question())
        self.assertIn("1a2b3c4d5e6f", out)
        self.assertIn("2026-09-03T10:00:00+02:00", out)
        self.assertIn('the commit says: "add build tooling"', out)
        self.assertIn("public/fonts/text.woff", out)
        self.assertIn("added in the same commit as the malware", out)

    def test_the_files_numbered_by_folder(self):
        out = render_delivery(_question())
        self.assertIn("1  (top level)", out)
        self.assertIn("2  .vscode/", out)
        self.assertIn("3  public/fonts/", out)
        self.assertIn("3.2 b.woff2", out)

    def test_what_the_commit_writes_reaches_the_terminal_defanged(self):
        out = render_delivery(_question(subject="ok\x1b[2J\n##[error]x", date="\x1b[31m",
                                        paths=("x/\x1b[31mred.js",)))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("##[", out)

    def test_each_counted_file_says_how_many_project_files_name_it(self):
        question = _question(named_by=((FILES[0], 2), (FILES[1], 0)))
        out = render_delivery(question)
        self.assertIn("(named by 2)", out)
        self.assertIn("(named by none)", out)
        self.assertEqual(2, out.count("(named by"))

    def test_two_files_whose_names_read_alike_are_told_apart(self):
        out = render_delivery(_question(paths=("dir/a.js", "dir/a.js\t")))
        self.assertIn("[111111111111]", out)
        self.assertIn("[222222222222]", out)

    def test_a_long_folder_says_choosing_it_takes_every_file(self):
        out = render_delivery(_question(paths=tuple(f"many/{n:02}.txt" for n in range(12))))
        self.assertIn("1.8 07.txt", out)
        self.assertNotIn("1.9", out)
        self.assertIn("4 more", out)

    def test_a_changed_file_is_named_apart_from_the_choice(self):
        out = render_delivery(_question(changed=(".gitignore",)))
        self.assertIn("it also changed, and saw leaves to you: .gitignore", out)


class TestTheAnswer(unittest.TestCase):

    def test_enter_keeps_every_file(self):
        self.assertEqual(KEEP, _ask(_question(), "")[0].action)

    def test_all_then_yes_takes_out_every_file(self):
        answer, _ = _ask(_question(), "all", "yes")
        self.assertEqual(TAKE_OUT, answer.action)
        self.assertEqual(set(FILES), set(answer.chosen))

    def test_numbers_choose_a_folder_or_one_file(self):
        answer, _ = _ask(_question(), "2 3.1", "yes")
        self.assertEqual({".vscode/launch.json", "public/fonts/a.woff2"}, set(answer.chosen))

    def test_a_bare_yes_is_not_an_answer_to_the_choice(self):
        answer, out = _ask(_question(), "y", "yes")
        self.assertEqual(UNANSWERED, answer.action)
        self.assertEqual((), answer.chosen)
        self.assertIn("'y' is not an answer here", out)

    def test_a_number_not_listed_is_asked_again(self):
        answer, out = _ask(_question(), "9", "1.5", "")
        self.assertEqual(KEEP, answer.action)
        self.assertIn("that names nothing listed", out)

    def test_end_of_input_is_unanswered(self):
        self.assertEqual(UNANSWERED, _ask(_question())[0].action)

    def test_answers_that_stay_unclear_are_unanswered(self):
        self.assertEqual(UNANSWERED, _ask(_question(), "y", "maybe", "remove")[0].action)

    def test_enter_at_the_confirmation_keeps_every_file(self):
        answer, _ = _ask(_question(), "all", "")
        self.assertEqual(KEEP, answer.action)
        self.assertEqual((), answer.chosen)

    def test_only_yes_confirms(self):
        answer, _ = _ask(_question(), "all", "y", "ok", "sure")
        self.assertEqual(UNANSWERED, answer.action)

    def test_end_of_input_at_the_confirmation_is_unanswered(self):
        self.assertEqual(UNANSWERED, _ask(_question(), "all")[0].action)


class TestTheBuiltResolver(unittest.TestCase):

    def test_a_delivery_is_put_as_a_delivery_question(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True

        with mock.patch.dict("os.environ", {"CI": ""}):
            with mock.patch("stayawake.utils.env.is_ci", return_value=False):
                resolver = build_resolver(Terminal("all\nyes\n"), Terminal())
        self.assertIsNotNone(resolver)
        answer = resolver(_question())
        self.assertEqual(TAKE_OUT, answer.action)


if __name__ == "__main__":
    unittest.main()
