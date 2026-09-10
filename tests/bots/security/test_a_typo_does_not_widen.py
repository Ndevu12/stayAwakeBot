#!/usr/bin/env python3
"""A named path that is not there stops the verb, rather than widening it to the parent.

Discovery falls back to a missing path's PARENT, so one typo reaches every repository beside the
one intended. A scan can absorb that; a verb that writes to them cannot."""
from __future__ import annotations

import ast
import io
import pathlib
import unittest
from unittest import mock

from stayawake.bots.security import remediator
from stayawake.bots.security.resolution import ScanOptions
from stayawake.utils.streaming import Streamer

ACTING_ON_WHAT_YOU_NAME = ("_amend_local", "_fix_local", "_discard_local")


class TestWhatIsNamedHasToBeThere(unittest.TestCase):
    def test_a_glob_may_match_nothing_and_is_not_a_typo(self):
        self.assertEqual(remediator.named_but_absent(["/nowhere/*", "/nowhere/?"]), [])

    def test_a_named_path_that_is_absent_is_one(self):
        self.assertEqual(remediator.named_but_absent(["/nowhere-at-all"]), ["/nowhere-at-all"])

    def test_one_that_is_there_is_not(self):
        self.assertEqual(remediator.named_but_absent([str(pathlib.Path.cwd())]), [])


class TestEveryVerbThatWritesChecksItFirst(unittest.TestCase):
    def test_each_one_refuses_and_says_what_was_not_found(self):
        for name in ACTING_ON_WHAT_YOU_NAME:
            out = io.StringIO()
            prog = Streamer(enabled=False, out=out)
            with self.subTest(verb=name):
                fn = getattr(remediator, name)
                with mock.patch.object(remediator, "_local_repos",
                                       side_effect=AssertionError("discovery ran on a typo")), \
                        mock.patch.object(remediator, "_preflight", return_value=None):
                    if name == "_discard_local":
                        got = fn({}, ScanOptions(), True, False, ["/nowhere-at-all"], prog)
                    elif name == "_fix_local":
                        got = fn({}, ScanOptions(), {}, [], ["/nowhere-at-all"], prog,
                                 publish=False, jobs=1)
                    else:
                        got = fn({}, ScanOptions(), {}, [], ["/nowhere-at-all"], prog, jobs=1)
                self.assertEqual(got, [])
                self.assertIn("no such path", out.getvalue())

    def test_none_of_them_asks_the_credential_about_a_typo(self):
        source = pathlib.Path("src/stayawake/bots/security/remediator.py").read_text()
        tree = ast.parse(source)
        for name in ACTING_ON_WHAT_YOU_NAME:
            fn = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef) and n.name == name)
            body = ast.get_source_segment(source, fn) or ""
            with self.subTest(verb=name):
                self.assertIn("named_but_absent", body)
                if "_preflight(" in body:
                    self.assertLess(body.index("named_but_absent"), body.index("_preflight("))

    def test_the_check_has_one_home(self):
        source = pathlib.Path("src/stayawake/bots/security/remediator.py").read_text()
        self.assertEqual(source.count("not Path(p).expanduser().exists()"), 1)


if __name__ == "__main__":
    unittest.main()
