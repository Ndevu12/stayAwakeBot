"""saw-platform keeps and releases a run's scratch folder exactly as main does."""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_PURPOSES = ["git outside any repository", "Reports for you", "---", "", "a/b c_d", "café ☃", "UPPER-case"]
_MAIN = """
import sys
from stayawake.utils import scratch
keep = sys.argv[1] == "keep"
scratch.new_dir("git outside any repository")
made = scratch.new_file("a key", suffix=".pem")
if keep:
    scratch.kept_dir("Reports for you")
print("made", flush=True)
sys.stdin.readline()
print(scratch.release_path(made))
print(len(scratch.release()))
"""


def _tree(base: Path) -> list:
    entries = []
    for path in sorted(base.rglob("*")):
        rel = str(path.relative_to(base))
        rel = re.sub(r"saw-run-[a-z0-9_]{8}", "saw-run-*", rel)
        rel = re.sub(r"\d{4}-\d{2}-\d{2}-\d{6}-[a-z0-9_]{8}", "STAMP-*", rel)
        rel = re.sub(r"tmp[a-z0-9_]{8}", "tmp*", rel)
        found = os.lstat(path)
        kind = "folder" if stat.S_ISDIR(found.st_mode) else "file"
        entries.append((rel, kind, stat.S_IMODE(found.st_mode)))
    return sorted(entries)


def _record(base: Path) -> str:
    records = list(base.glob("saw-run-*/run.json"))
    if not records:
        return ""
    text = records[0].read_text()
    return re.sub(r'"(pid|uid)": \d+', r'"\1": N', text).replace(str(base), "TMP")


@unittest.skipUnless(shutil.which("cargo") and os.name == "posix", "needs cargo on Unix")
class ScratchMatchesMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "scratch_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "scratch_probe"

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="scratch-")).resolve()
        self.addCleanup(shutil.rmtree, self.work, True)

    def run_side(self, argv: list[str], temp: Path) -> tuple:
        env = {**os.environ, "TMPDIR": str(temp), "PYTHONPATH": str(REPO_ROOT / "src")}
        temp.mkdir()
        side = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
        self.assertEqual(side.stdout.readline().strip(), "made")
        made, record = _tree(temp), _record(temp)
        released, _ = side.communicate("\n", timeout=60)
        return made, record, released.split(), _tree(temp)

    def test_a_run_is_kept_and_released_as_on_main(self):
        for keep in ("keep", "nokeep"):
            with self.subTest(keep=keep):
                main = self.run_side([sys.executable, "-c", _MAIN, keep], self.work / f"main-{keep}")
                rust = self.run_side([str(self.tool), str(self.work / f"rust-{keep}"), keep], self.work / f"rust-{keep}")
                self.assertEqual(rust[0], main[0])
                self.assertEqual(rust[1].replace(str(self.work / f"rust-{keep}"), "TMP"), main[1].replace(str(self.work / f"main-{keep}"), "TMP"))
                self.assertIn("Not a directory", " ".join(main[2][:-1]))
                self.assertEqual(rust[2], ["0"])
                self.assertEqual(main[2][-1], "0")
                only_main, only_rust = sorted(set(main[3]) - set(rust[3])), sorted(set(rust[3]) - set(main[3]))
                if keep == "keep":
                    self.assertEqual(only_main, [("saw-run-*/a-key", "folder", 0o700), ("saw-run-*/a-key/tmp*.pem", "file", 0o700)])
                    self.assertEqual(only_rust, [("saw-run-*/a-key", "folder", 0o755)])
                else:
                    self.assertEqual((only_main, only_rust), ([], []))

    def test_purposes_name_the_same_folders(self):
        from stayawake.utils import scratch
        printed = subprocess.run([str(self.tool), "slugs", *_PURPOSES], capture_output=True, text=True, check=True).stdout
        self.assertEqual(printed.split("\n")[:-1], [scratch._slug(p) for p in _PURPOSES])


if __name__ == "__main__":
    unittest.main()
