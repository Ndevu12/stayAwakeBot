"""saw-platform walks a folder and windows a file exactly as main does."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.targets import base
from stayawake.bots.security.targets.base import ScanOptions, Target

REPO_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class FileReadingMatchesMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "files_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "files_probe"

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="file-reading-")).resolve()
        self.addCleanup(shutil.rmtree, self.work, True)

    def probe(self, *args: str):
        return json.loads(subprocess.run([str(self.tool), *args], capture_output=True, text=True, check=True).stdout)

    def test_a_walk_lists_what_mains_walk_lists_in_the_same_order(self):
        tree = self.work / "tree"
        for rel in ("a.js", "z.txt", "sub/b.js", "sub/deeper/c.py", "node_modules/x.js", "keep/node_modules/y.js",
                    "café/d.md", "other/e.js"):
            (tree / rel).parent.mkdir(parents=True, exist_ok=True)
            (tree / rel).write_text("x\n")
        os.symlink(tree / "other", tree / "linked-folder")
        os.symlink(tree / "a.js", tree / "linked-file.js")
        os.symlink(tree / "missing", tree / "dangling")
        os.mkfifo(tree / "pipe.js")
        target = Target(tree, "tree", ScanOptions(exclude_dirs={"node_modules"}))
        main_files = list(target.iter_files())
        rust = self.probe("walk", str(tree), "node_modules")
        self.assertEqual(rust["files"], main_files)
        self.assertEqual(rust["pruned"], sorted(target.pruned_dirs))

    def test_windows_match_mains_windows(self):
        lines = [f"line {i} " + "x" * (i % 37) for i in range(4000)]
        text = "\n".join(lines) + "\n"
        path = self.work / "long.js"
        path.write_text(text)
        size = path.stat().st_size
        for window in (1, 7, 4096, 65_536, 200_000, size, size + 10):
            with self.subTest(window=window):
                with path.open("rb") as handle:
                    main_windows = [[offset, chunk.decode("utf-8", "replace")]
                                    for offset, chunk in base._byte_windows(handle.read, size, window)]
                self.assertEqual(self.probe("windows", str(path), str(window), str(base._SOURCE_WINDOW_OVERLAP)), main_windows)


if __name__ == "__main__":
    unittest.main()
