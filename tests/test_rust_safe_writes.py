"""saw-platform writes saw's own files exactly as main does, refusing the same links."""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.utils import atomicwrite, pathsafe

REPO_ROOT = Path(__file__).resolve().parents[1]
_LINKS = {"refuse": atomicwrite.REFUSE_A_LINK, "follow": atomicwrite.FOLLOW_A_TRUSTED_LINK,
          "replace": atomicwrite.REPLACE_A_LINK}


def _build(root: Path, scenario: str) -> Path:
    root.mkdir(parents=True)
    os.chmod(root, 0o755)
    (root / "real").mkdir()
    (root / "real" / "target.json").write_text("old")
    if scenario == "keeps-mode":
        (root / "file.json").write_text("before")
        os.chmod(root / "file.json", 0o640)
        return root / "file.json"
    if scenario == "link-at-name":
        os.symlink(root / "real" / "target.json", root / "link.json")
        return root / "link.json"
    if scenario in ("shared-holder", "private-holder"):
        (root / "holder").mkdir()
        os.symlink(root / "real", root / "holder" / "way")
        os.chmod(root / "holder", 0o757 if scenario == "shared-holder" else 0o755)
        return root / "holder" / "way" / "file.json"
    if scenario == "loop":
        os.symlink(root / "b", root / "a")
        os.symlink(root / "a", root / "b")
        return root / "a" / "file.json"
    if scenario == "dangling":
        os.symlink(root / "real" / "missing.json", root / "dangling.json")
        return root / "dangling.json"
    if scenario == "relative-up":
        (root / "here").mkdir()
        os.symlink("../real/target.json", root / "here" / "up.json")
        return root / "here" / "up.json"
    if scenario == "link-to-folder":
        os.symlink("..", root / "to-folder")
        return root / "to-folder"
    return root / "made" / "on" / "the" / "way" / "file.json"


def _tree(root: Path) -> list:
    entries = []
    for here, folders, files in os.walk(root):
        for name in sorted(folders + files):
            path = Path(here) / name
            found = os.lstat(path)
            kind = "link" if stat.S_ISLNK(found.st_mode) else "folder" if stat.S_ISDIR(found.st_mode) else "file"
            content = (path.read_text() if kind == "file"
                       else os.readlink(path).replace(str(root), "<root>") if kind == "link" else "")
            entries.append((str(path.relative_to(root)), kind, content, stat.S_IMODE(found.st_mode)))
        folders[:] = [f for f in folders if not (Path(here) / f).is_symlink()]
    return sorted(entries)


@unittest.skipUnless(shutil.which("cargo") and os.name == "posix", "needs cargo on Unix")
class SafeWritesMatchMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "write_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "write_probe"

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="safe-writes-")).resolve()
        self.addCleanup(shutil.rmtree, self.work, True)

    def _main(self, path: Path, mode: str, link: str) -> str:
        try:
            with atomicwrite.staged(path, mode=None if mode == "plain" else int(mode, 8), binary=True,
                                    at_a_link=_LINKS[link]) as handle:
                handle.write(b"new")
            return "written"
        except pathsafe.RedirectedPath:
            return "redirected"
        except OSError:
            return "failed"

    def test_every_scenario_ends_as_it_does_on_main(self):
        scenarios = ["new-nested", "keeps-mode", "link-at-name", "shared-holder", "private-holder", "loop", "dangling",
                     "relative-up", "link-to-folder"]
        outcomes = set()
        for scenario in scenarios:
            for link in _LINKS:
                for mode in ("600", "plain"):
                    with self.subTest(scenario=scenario, link=link, mode=mode):
                        main_root, rust_root = self.work / f"{scenario}-{link}-{mode}-main", self.work / f"{scenario}-{link}-{mode}-rust"
                        main_answer = self._main(_build(main_root, scenario), mode, link)
                        target = _build(rust_root, scenario)
                        rust_answer = subprocess.run([str(self.tool), str(target), "new", mode, link], capture_output=True,
                                                     text=True, check=True).stdout.strip()
                        self.assertEqual(rust_answer, main_answer)
                        self.assertEqual(_tree(rust_root), _tree(main_root))
                        outcomes.add(main_answer)
        self.assertEqual(outcomes, {"written", "redirected"})


if __name__ == "__main__":
    unittest.main()
