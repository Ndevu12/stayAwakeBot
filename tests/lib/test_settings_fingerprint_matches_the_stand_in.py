#!/usr/bin/env python3
"""saw and its git stand-in read the same fingerprint of the programs a repository's own git settings
start: both read every case in `bots/mcp/session/tests/settings_fingerprint_cases.json`, the stand-in's
crate tests in Rust and this module against `settings_fingerprint`."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib.git import settings_fingerprint
from stayawake.lib.git.run import real_git

CASES_FILE = (Path(__file__).resolve().parents[2] / "src" / "stayawake" / "bots" / "mcp" / "session" / "tests"
              / "settings_fingerprint_cases.json")
ROOT = "@ROOT@"


def build(root: Path, case: dict, operator: str, git: str) -> dict:
    """Make the repository one case reads. Takes the case's folder, the case, the operator's default
    settings and the git to make it with. Returns the environment the case reads it in."""
    shown = os.path.realpath(root)
    global_config = Path(shown) / ".gitconfig"
    global_config.write_text(case.get("operator_settings", operator).replace(ROOT, shown), encoding="utf-8")
    subprocess.run([git, "init", "-q", str(root / "repo")], check=True, stdin=subprocess.DEVNULL,
                   env={"HOME": shown, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                        "PATH": os.environ.get("PATH", "")})
    config = root / "repo" / ".git" / "config"
    config.write_text(config.read_text(encoding="utf-8") + case["settings"], encoding="utf-8")
    for path, contents in case["files"].items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(contents.encode("utf-8"))
    return {"HOME": shown, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(global_config)}


@unittest.skipIf(os.name == "nt", "the git stand-in runs on Linux and macOS")
class TheFingerprintMatchesTheStandIn(unittest.TestCase):
    def test_every_shared_case_reads_the_same_fingerprint(self):
        cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
        git = real_git()
        self.assertIsNotNone(git)
        for case in cases["cases"]:
            with self.subTest(case["name"]):
                root = Path(tempfile.mkdtemp(prefix="saw-fingerprint-"))
                self.addCleanup(shutil.rmtree, root, True)
                environment = build(root, case, cases["operator_settings"], git)
                with mock.patch.dict(os.environ, environment):
                    found = settings_fingerprint.fingerprint(root / "repo")
                self.assertIsInstance(found, settings_fingerprint.Fingerprint, found)
                shown = os.path.realpath(root)
                expected = tuple(tuple(part.replace(ROOT, shown) for part in entry) for entry in case["expected"])
                self.assertEqual(found.entries, expected)
                self.assertEqual(found.empty, not expected)
                if "digest" in case:
                    self.assertEqual(found.digest(), case["digest"])

    def test_a_folder_in_no_repository_has_none(self):
        root = tempfile.mkdtemp(prefix="saw-fingerprint-")
        self.addCleanup(shutil.rmtree, root, True)
        with mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": os.path.dirname(os.path.realpath(root))}):
            self.assertIsNone(settings_fingerprint.fingerprint(root))


if __name__ == "__main__":
    unittest.main()
