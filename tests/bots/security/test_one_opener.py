#!/usr/bin/env python3
"""One place opens a file for reading, so one place can enforce what must not be read.

Three separate call sites in `targets/base.py` each opened their own handle. Two applied the
write-sink rule and the third did not, so a scan of an ordinary project read a linked-to SSH key
and put 48 verbatim bytes of it into the report, the SARIF and the saved bundle. The rule was
correct and the enforcement was not in every path — this ratchet is what makes "every path" a
thing the suite can check.
"""
from __future__ import annotations

import ast
import inspect
import unittest

from stayawake.bots.security.targets import base


class TestTheReaderHasOneOpener(unittest.TestCase):
    def setUp(self):
        self.source = inspect.getsource(base)

    def test_only_one_call_site_opens_a_file(self):
        # Parsed, not grepped: the first version of this test counted the word `open()` in a
        # comment and failed on correct code.
        opens = [n for n in ast.walk(ast.parse(self.source))
                 if isinstance(n, ast.Call)
                 and ((isinstance(n.func, ast.Attribute) and n.func.attr == "open")
                      or (isinstance(n.func, ast.Name) and n.func.id == "open"))]
        self.assertEqual(len(opens), 1,
                         f"{len(opens)} call sites open a file; every one of them has to remember "
                         "the write-sink rule. Route the new one through Target._open_read.")

    def test_that_call_site_is_the_guarded_one(self):
        opener = inspect.getsource(base.Target._open_read)
        self.assertIn(".open(", opener)
        self.assertIn("_redirects_into_a_sink", opener)

    def test_every_reader_goes_through_it(self):
        for name in ("read_bytes", "_head_tail", "read_source_windows"):
            body = inspect.getsource(getattr(base.Target, name))
            self.assertIn("_open_read", body, f"{name} does not read through the one opener")


if __name__ == "__main__":
    unittest.main()
