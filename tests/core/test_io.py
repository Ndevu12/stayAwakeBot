#!/usr/bin/env python3
"""resolve_writable_dir: report writing must degrade gracefully on an unwritable dir,
never crash a completed run."""
from __future__ import annotations

import contextlib
import io as _io
import tempfile
import unittest
from pathlib import Path

from stayawake.core.io import resolve_writable_dir, write_json


class TestResolveWritableDir(unittest.TestCase):
    def test_writable_preferred_is_used_silently(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "reports" / "security"
            err = _io.StringIO()
            with contextlib.redirect_stderr(err):
                got = resolve_writable_dir(target, label="security reports")
            self.assertEqual(got, target)
            self.assertTrue(got.is_dir())
            self.assertEqual(err.getvalue(), "")            # no warning on the happy path

    def test_unwritable_preferred_falls_back_and_warns(self):
        # Force an unwritable preferred path in a uid-independent way: make its parent a
        # regular FILE so mkdir raises NotADirectoryError for any user — unlike chmod, which
        # root ignores (and CI/test runners are often root).
        with tempfile.TemporaryDirectory() as d:
            blocker = Path(d) / "blocker"
            blocker.write_text("not a dir\n")
            target = blocker / "security"               # parent is a file -> mkdir fails
            err = _io.StringIO()
            with contextlib.redirect_stderr(err):
                got = resolve_writable_dir(target, label="security reports")
            self.assertNotEqual(got, target)
            self.assertTrue(got.is_dir())
            warning = err.getvalue()
            self.assertIn("not writable", warning)          # warned…
            self.assertIn(str(target), warning)             # …naming the path we couldn't use
            # and the fallback is genuinely writable
            write_json(got / "latest.json", {"ok": True})
            self.assertTrue((got / "latest.json").exists())


if __name__ == "__main__":
    unittest.main()
