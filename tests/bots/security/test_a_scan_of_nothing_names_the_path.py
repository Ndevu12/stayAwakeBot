#!/usr/bin/env python3
"""A scan whose named paths give nothing to scan names each path and why, and says nothing was
scanned."""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.service import run

_NEEDS_POSIX_NONROOT = (os.name == "posix"
                        and not (hasattr(os, "geteuid") and os.geteuid() == 0))


class TestEachPathIsNamedWithWhyNothingWasScanned(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="nothing-"))
        self.addCleanup(shutil.rmtree, self.home, True)

    def test_a_path_that_is_not_there_says_so(self):
        missing = str(self.home / "missing")
        self.assertEqual(run._why_nothing_at(missing), f"{missing} does not exist")

    def test_a_pattern_that_matches_nothing_says_so(self):
        pattern = str(self.home / "*.none")
        self.assertEqual(run._why_nothing_at(pattern), f"{pattern} matched nothing")

    @unittest.skipUnless(_NEEDS_POSIX_NONROOT, "needs a POSIX account that permissions apply to")
    def test_a_path_inside_a_folder_this_account_cannot_open_names_the_folder(self):
        shut = self.home / "shut"
        shut.mkdir()
        self.addCleanup(os.chmod, shut, 0o700)
        os.chmod(shut, 0)
        inside = str(shut / "repo")
        self.assertEqual(run._why_nothing_at(inside),
                         f"{inside} is inside {shut}, which this account cannot open")

    def test_the_scan_names_every_path_and_says_nothing_was_scanned(self):
        first, second = str(self.home / "one"), str(self.home / "two")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = run.scan(paths=[first, second])
        self.assertNotEqual(code, 0)
        self.assertIn(f"error: {first} does not exist.", err.getvalue())
        self.assertIn(f"error: {second} does not exist.", err.getvalue())
        self.assertIn("Nothing was scanned.", err.getvalue())


if __name__ == "__main__":
    unittest.main()
