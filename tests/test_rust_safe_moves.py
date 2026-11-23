"""saw-platform sets modes, makes folders, renames, moves and copies exactly as main does."""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.utils import atomicwrite, pathsafe

REPO_ROOT = Path(__file__).resolve().parents[1]


def _tree(root: Path) -> list:
    entries = []
    for here, folders, files in os.walk(root):
        for name in sorted(folders + files):
            path = Path(here) / name
            found = os.lstat(path)
            kind = "link" if stat.S_ISLNK(found.st_mode) else "folder" if stat.S_ISDIR(found.st_mode) else "file"
            content = path.read_text() if kind == "file" else os.readlink(path) if kind == "link" else ""
            entries.append((str(path.relative_to(root)), kind, content, stat.S_IMODE(found.st_mode)))
        folders[:] = [f for f in folders if not (Path(here) / f).is_symlink()]
    return sorted(entries)


def _scene(root: Path) -> None:
    root.mkdir(parents=True)
    os.chmod(root, 0o755)
    (root / "file.txt").write_text("one")
    (root / "linked.txt").write_text("two")
    os.link(root / "linked.txt", root / "second-name.txt")
    os.symlink("file.txt", root / "pointer.txt")
    (root / "taken").mkdir()
    (root / "tree" / "inner").mkdir(parents=True)
    (root / "tree" / "inner" / "deep.js").write_text("deep")
    os.chmod(root / "tree" / "inner" / "deep.js", 0o640)
    os.symlink("inner/deep.js", root / "tree" / "link.js")
    os.utime(root / "tree" / "inner" / "deep.js", ns=(1_600_000_000_000_000_000, 1_600_000_000_123_456_789))
    (root / "out").mkdir()


@unittest.skipUnless(shutil.which("cargo") and os.name == "posix", "needs cargo on Unix")
class SafeMovesMatchMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "moves_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "moves_probe"

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="safe-moves-")).resolve()
        self.addCleanup(shutil.rmtree, self.work, True)

    def _main(self, op: str, r: Path) -> str:
        try:
            if op == "set_mode file":
                atomicwrite.set_mode(r / "file.txt", 0o600)
            elif op == "set_mode hard-linked":
                atomicwrite.set_mode(r / "linked.txt", 0o600)
            elif op == "set_mode through a link":
                atomicwrite.set_mode(r / "pointer.txt", 0o600)
            elif op == "new_folder taken":
                return f"done {atomicwrite.new_folder(r, 'taken', mode=0o755).name}"
            elif op == "rename_in":
                atomicwrite.rename_in(r, "file.txt", "renamed.txt")
            elif op == "rename_beside free":
                atomicwrite.rename_beside(r, "file.txt", "free.txt")
            elif op == "rename_beside taken":
                atomicwrite.rename_beside(r, "file.txt", "linked.txt")
            elif op == "move_into":
                atomicwrite.move_into(r / "tree", r / "out", "moved")
            elif op == "copy tree":
                origin, destination = pathsafe.open_folder(r), pathsafe.open_folder(r / "out")
                try:
                    return f"done {str(atomicwrite._copy_into(origin, 'tree', destination, 'copied')).lower()}"
                finally:
                    os.close(origin)
                    os.close(destination)
            elif op == "not one entry":
                atomicwrite.rename_in(r, "file.txt", "../escaped.txt")
            return "done"
        except pathsafe.RedirectedPath:
            return "redirected"
        except FileExistsError:
            return "exists"
        except OSError:
            return "failed"

    def _rust(self, op: str, r: Path) -> str:
        args = {
            "set_mode file": ["set_mode", r / "file.txt", "600"],
            "set_mode hard-linked": ["set_mode", r / "linked.txt", "600"],
            "set_mode through a link": ["set_mode", r / "pointer.txt", "600"],
            "new_folder taken": ["new_folder", r, "taken"],
            "rename_in": ["rename_in", r, "file.txt", "renamed.txt"],
            "rename_beside free": ["rename_beside", r, "file.txt", "free.txt"],
            "rename_beside taken": ["rename_beside", r, "file.txt", "linked.txt"],
            "move_into": ["move_into", r / "tree", r / "out", "moved"],
            "copy tree": ["copy", r, "tree", r / "out", "copied"],
            "not one entry": ["rename_in", r, "file.txt", "../escaped.txt"],
        }[op]
        return subprocess.run([str(self.tool), *map(str, args)], capture_output=True, text=True, check=True).stdout.strip()

    def _times(self, top: Path) -> dict:
        return {str(path.relative_to(top)): os.lstat(path).st_mtime_ns
                for path in [top, *top.rglob("*")] if not path.is_symlink()}

    def test_every_operation_ends_as_it_does_on_main(self):
        operations = ["set_mode file", "set_mode hard-linked", "set_mode through a link", "new_folder taken", "rename_in",
                      "rename_beside free", "rename_beside taken", "move_into", "copy tree", "not one entry"]
        answers = set()
        for op in operations:
            with self.subTest(op=op):
                main_root, rust_root = self.work / f"{op}-main", self.work / f"{op}-rust"
                _scene(main_root)
                _scene(rust_root)
                main_answer, rust_answer = self._main(op, main_root), self._rust(op, rust_root)
                self.assertEqual(rust_answer, main_answer)
                self.assertEqual(_tree(rust_root), _tree(main_root))
                if op == "copy tree":
                    for root in (main_root, rust_root):
                        self.assertEqual(self._times(root / "out" / "copied"), self._times(root / "tree"))
                answers.add(main_answer.split()[0])
        self.assertEqual(answers, {"done", "redirected", "exists"})


if __name__ == "__main__":
    unittest.main()
