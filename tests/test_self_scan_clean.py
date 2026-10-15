#!/usr/bin/env python3
"""saw's own committed files scan clean with no allowlist, and so does what Python compiles from them. A test
that needs a sample payload builds it when it runs, through tests/support/samples.py."""
from __future__ import annotations

import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.service.config import _options
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget

REPO = Path(__file__).resolve().parents[1]


def _tracked_files() -> tuple[str, ...]:
    """List the committed files that exist on disk. Returns their repository-relative paths, or nothing
    when this is not a git checkout."""
    try:
        out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ()
    return tuple(p for p in out.split("\0") if p and (REPO / p).is_file())


def _findings_in(root: Path, files: tuple[str, ...]) -> list[str]:
    with LocalRepoTarget(str(root), "self", _options({}), include_only=files) as target:
        result = scan_target(target, load_signatures(), [])
    wanted = set(files)
    return sorted(f"{f.signature_id} in {f.path}" for f in result.findings if f.path in wanted)


class TestSawsOwnTreeScansClean(unittest.TestCase):
    def setUp(self):
        self.tracked = _tracked_files()
        if not self.tracked:
            self.skipTest("not a git checkout")

    def test_no_committed_file_has_a_finding_with_no_allowlist(self):
        self.assertEqual(_findings_in(REPO, self.tracked), [],
                         "build the sample when the test runs, through tests/support/samples.py")

    def test_nothing_python_compiles_from_them_has_a_finding(self):
        root = Path(tempfile.mkdtemp(prefix="self-scan-compiled-"))
        self.addCleanup(shutil.rmtree, root, True)
        compiled = []
        for path in self.tracked:
            if path.endswith(".py"):
                target = Path(path).with_suffix(f".{sys.implementation.cache_tag}.pyc")
                (root / target).parent.mkdir(parents=True, exist_ok=True)
                py_compile.compile(str(REPO / path), cfile=str(root / target), doraise=True)
                compiled.append(str(target))
        self.assertTrue(compiled)
        self.assertEqual(_findings_in(root, tuple(compiled)), [],
                         "join a sample's pieces when the test runs (samples.joined), never with + or "
                         "side by side, which Python joins when it compiles")


if __name__ == "__main__":
    unittest.main()
