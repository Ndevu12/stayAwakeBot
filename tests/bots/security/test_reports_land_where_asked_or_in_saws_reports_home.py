"""A scan writes its reports to the folder it was given, or to saw's reports home with an error naming
both, and keeps its verdict either way."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


class ReportsLandWhereAskedOrInSawsReportsHome(unittest.TestCase):

    def test_an_unwritable_reports_folder_sends_the_reports_to_saws_reports_home(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            tree = work / "tree"
            tree.mkdir()
            (tree / "index.js").write_text("module.exports = 1;\n")
            (work / "blocker").write_text("not a folder\n")
            asked = work / "blocker" / "reports"
            done = subprocess.run([sys.executable, "-m", "stayawake", "scan", str(tree), "-d", str(asked), "--no-stream"],
                                  capture_output=True, text=True, timeout=300,
                                  env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src"), "XDG_STATE_HOME": str(work / "state")})
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn(f"error: security reports directory {asked} cannot be written", done.stderr)
            home = work / "state" / "saw" / "reports" / "security-reports"
            kept = [folder for folder in home.iterdir()]
            self.assertEqual(len(kept), 1)
            self.assertTrue((kept[0] / "latest.md").is_file())
            self.assertIn(f"saw wrote the security reports to {kept[0]} instead.", done.stderr)
            self.assertEqual(sorted(p.name for p in work.iterdir()), ["blocker", "state", "tree"])


if __name__ == "__main__":
    unittest.main()
