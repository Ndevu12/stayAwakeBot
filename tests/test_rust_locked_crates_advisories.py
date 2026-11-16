"""Every outside crate saw locks has no known security advisory, judged by saw's own scan against its
offline advisory database. The check needs that database's cargo records (`saw db update -e cargo`);
without them it is skipped, saying so, rather than passing."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_RUN_SAW = "import sys; from stayawake.cli import main; sys.argv = ['saw', *sys.argv[1:]]; main()"
_HAS_CARGO_RECORDS = ("import json, sys; from stayawake.bots.security.dependencies.db import cache_status; "
                      "print(json.dumps('cargo' in (cache_status().get('ecosystems') or {})))")


def _python(code: str, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    return subprocess.run([sys.executable, "-c", code, *args], capture_output=True, text=True, env=env, check=False)


def _lockfiles() -> list[Path]:
    with (REPO_ROOT / "Cargo.toml").open("rb") as handle:
        excluded = tomllib.load(handle)["workspace"].get("exclude", [])
    return [REPO_ROOT / "Cargo.lock", *(REPO_ROOT / folder / "Cargo.lock" for folder in excluded)]


def advisories_in(lockfile_text: str) -> list[str]:
    """The evidence of each advisory saw's scan reports for one Cargo.lock."""
    with tempfile.TemporaryDirectory() as scratch:
        (Path(scratch) / "Cargo.lock").write_text(lockfile_text)
        result = _python(_RUN_SAW, "scan", scratch, "--json", "--no-stream")
    report = json.loads(result.stdout)
    return [advisory["evidence"] for target in report["results"] for advisory in target["advisories"]]


class LockedCratesHaveNoKnownAdvisory(unittest.TestCase):

    def setUp(self):
        status = _python(_HAS_CARGO_RECORDS)
        if status.returncode != 0:
            self.skipTest(f"saw could not be loaded to read its advisory database: {status.stderr.strip()[-300:]}")
        if not json.loads(status.stdout):
            self.skipTest("saw's advisory database has no cargo records; run `saw db update -e cargo` first")

    def test_no_locked_crate_has_a_known_advisory(self):
        for lockfile in _lockfiles():
            with self.subTest(lockfile=str(lockfile.relative_to(REPO_ROOT))):
                self.assertEqual(advisories_in(lockfile.read_text()), [])

    def test_a_crate_with_a_known_advisory_is_reported(self):
        withdrawn = ('version = 4\n\n[[package]]\nname = "serde_yml"\nversion = "0.0.12"\n'
                     'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
        found = advisories_in(withdrawn)
        self.assertTrue(found)
        self.assertTrue(all("serde_yml@0.0.12" in evidence for evidence in found), found)


if __name__ == "__main__":
    unittest.main()
