#!/usr/bin/env python3
"""A bare or mirror clone has no checked-out files, so a scan of it is refused and never reads as
clean; the checkout a normal clone has is still scanned."""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stayawake.bots.security.service.run import scan

_PAYLOAD = "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"


def _git(*args: str) -> None:
    subprocess.run(["git", *args], check=True, capture_output=True)


def _infected_repo(top: Path) -> Path:
    repo = top / "work"
    _git("init", "-q", "-b", "main", str(repo))
    for key, value in (("user.email", "t@t"), ("user.name", "t"), ("commit.gpgsign", "false")):
        _git("-C", str(repo), "config", key, value)
    (repo / ".gitignore").write_text(_PAYLOAD)
    _git("-C", str(repo), "add", "-A")
    _git("-C", str(repo), "commit", "-qm", "payload")
    return repo


def _scan(path: Path) -> dict:
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        scan(paths=[str(path)], json_out=True, no_stream=True)
    return json.loads(out.getvalue())["results"][0]


class TestABareRepository(unittest.TestCase):
    def setUp(self):
        self.top = Path(tempfile.mkdtemp(prefix="bare-"))
        self.addCleanup(shutil.rmtree, self.top, True)
        self.repo = _infected_repo(self.top)

    def test_a_mirror_clone_is_refused_not_clean(self):
        mirror = self.top / "repo.git"
        _git("clone", "-q", "--mirror", str(self.repo), str(mirror))
        self.assertIn("no checked-out files", _scan(mirror).get("error") or "")

    def test_a_bare_clone_is_refused_not_clean(self):
        bare = self.top / "bare.git"
        _git("clone", "-q", "--bare", str(self.repo), str(bare))
        self.assertIn("no checked-out files", _scan(bare).get("error") or "")

    def test_the_checkout_is_still_scanned(self):
        result = _scan(self.repo)
        self.assertEqual("infected", result.get("verdict"))
        self.assertFalse(result.get("error"))


if __name__ == "__main__":
    unittest.main()
