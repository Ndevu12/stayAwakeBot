"""The Rust saw's release comes only from the build."""

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def rust_version_line(target_dir: Path, release: str | None) -> str:
    """Build `saw` with `release` passed in (or none) and return what `saw --version` prints."""
    env = {key: value for key, value in os.environ.items() if key != "SAW_RELEASE"}
    if release is not None:
        env["SAW_RELEASE"] = release
    subprocess.run(["cargo", "build", "--quiet", "--locked", "-p", "saw-cli", "--target-dir", str(target_dir)],
                   cwd=REPO_ROOT, env=env, check=True)
    shown = subprocess.run([str(target_dir / "debug" / "saw"), "--version"],
                           capture_output=True, text=True, check=True)
    return shown.stdout.strip()


def python_version_line() -> str:
    """Return what the Python `saw --version` prints."""
    from stayawake.cli import main

    printed = io.StringIO()
    with contextlib.redirect_stdout(printed), contextlib.suppress(SystemExit):
        main(["--version"])
    return printed.getvalue().strip()


@unittest.skipIf(shutil.which("cargo") is None, "cargo is not installed, so the Rust saw cannot be built")
class TheReleaseComesFromTheBuild(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(scratch.cleanup)
        cls.target_dir = Path(scratch.name)

    def test_a_release_build_reports_its_release(self):
        self.assertEqual(rust_version_line(self.target_dir, "9.9.9"), "saw (stayawakebot) 9.9.9")

    def test_a_build_without_a_release_says_so(self):
        self.assertEqual(rust_version_line(self.target_dir, None), "saw (stayawakebot) 0+unknown")

    def test_the_line_has_the_python_saws_form(self):
        python_line = python_version_line()
        release = python_line.rsplit(" ", 1)[-1]
        self.assertEqual(rust_version_line(self.target_dir, release), python_line)


if __name__ == "__main__":
    unittest.main()
