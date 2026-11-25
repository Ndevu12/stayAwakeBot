"""A scan writes its reports only to the folder it was given, and keeps its verdict when that folder
cannot take them."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


class ReportsGoOnlyWhereAsked(unittest.TestCase):

    def test_an_unwritable_reports_folder_gets_nothing_and_the_verdict_stands(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            tree = work / "tree"
            tree.mkdir()
            (tree / "index.js").write_text("module.exports = 1;\n")
            (work / "blocker").write_text("not a folder\n")
            asked = work / "blocker" / "reports"
            done = subprocess.run([sys.executable, "-m", "stayawake", "scan", str(tree), "-d", str(asked), "--no-stream"],
                                  capture_output=True, text=True, timeout=300,
                                  env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")})
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn(f"error: security reports directory {asked} cannot be written", done.stderr)
            self.assertNotIn("latest.md", done.stdout + done.stderr)
            self.assertEqual(sorted(p.name for p in work.iterdir()), ["blocker", "tree"])


if __name__ == "__main__":
    unittest.main()
