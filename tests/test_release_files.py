#!/usr/bin/env python3
"""The files a release publishes for clients: the platform manifest, the requirements lock and the
SBOM, named for the release, with every wheel placed and every dependency hashed."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / ".github" / "scripts" / "release_files.py"
_spec = importlib.util.spec_from_file_location("release_files", SCRIPT)
release_files = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_files)

VERSION = "0.17.6"
TAGS = ("macosx_11_0_arm64", "macosx_11_0_x86_64", "manylinux_2_28_aarch64", "manylinux_2_28_x86_64",
        "win_amd64")
DEPENDENCIES = """\
aiohttp==3.14.5 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
typing-extensions==4.16.0 ; python_full_version < '3.13' \\
    --hash=sha256:cccc
"""
CHANGELOG = """\
## [Unreleased]

### Security
- not this one

## [0.17.6] - 2026-11-25

### Fixed
- a fix

## [0.17.5] - 2026-11-24

### Security
- an older one
"""


def _wheel(folder: Path, tag: str, version: str = VERSION) -> Path:
    path = folder / f"stayawakebot-{version}-py3-none-{tag}.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"stayawakebot-{version}.dist-info/METADATA",
                         f"Metadata-Version: 2.4\nName: stayawakebot\nVersion: {version}\n"
                         f"Requires-Python: >=3.11\n\n")
    return path


class AReleaseWritesWhatClientsRead(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.dist = self.tmp / "dist"
        self.dist.mkdir()
        (self.dist / f"stayawakebot-{VERSION}.tar.gz").write_bytes(b"sdist")
        self.wheels = [_wheel(self.dist, tag) for tag in TAGS]
        (self.tmp / "dependencies.lock").write_text(DEPENDENCIES)
        (self.tmp / "CHANGELOG.md").write_text(CHANGELOG)
        (self.tmp / "sbom.cdx.json").write_text('{"components": []}')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self) -> list[Path]:
        return release_files.write(self.dist, self.tmp / "dependencies.lock", self.tmp / "CHANGELOG.md",
                                   self.tmp / "sbom.cdx.json", self.tmp / "out")

    def test_the_three_files_are_named_for_the_release(self):
        self.assertEqual(sorted(p.name for p in self._write()),
                         [f"stayawakebot-{VERSION}.platforms.json", f"stayawakebot-{VERSION}.requirements.lock",
                          f"stayawakebot-{VERSION}.sbom.cdx.json"])

    def test_the_manifest_places_every_wheel_with_its_hash_and_minimum(self):
        self._write()
        manifest = json.loads((self.tmp / "out" / f"stayawakebot-{VERSION}.platforms.json").read_text())
        self.assertEqual((manifest["contract"], manifest["version"], manifest["security"]), (1, VERSION, False))
        self.assertEqual(manifest["requirements_lock"], f"stayawakebot-{VERSION}.requirements.lock")
        placed = {(w["os"], w["arch"]): w for w in manifest["wheels"]}
        self.assertEqual(sorted(placed), [("linux", "arm64"), ("linux", "x86_64"), ("macos", "arm64"),
                                          ("macos", "x86_64"), ("windows", "x86_64")])
        linux = placed[("linux", "x86_64")]
        self.assertEqual((linux["libc"], linux["minimum"], linux["requires_python"]), ("glibc", "2.28", ">=3.11"))
        self.assertEqual(placed[("macos", "arm64")]["minimum"], "11.0")
        for wheel in self.wheels:
            entry = next(w for w in manifest["wheels"] if w["file"] == wheel.name)
            self.assertEqual(entry["sha256"], hashlib.sha256(wheel.read_bytes()).hexdigest())

    def test_the_lock_pins_saw_by_every_built_file_then_its_dependencies(self):
        self._write()
        lock = (self.tmp / "out" / f"stayawakebot-{VERSION}.requirements.lock").read_text()
        self.assertTrue(lock.startswith(f"stayawakebot=={VERSION} \\\n"))
        for built in [*self.wheels, self.dist / f"stayawakebot-{VERSION}.tar.gz"]:
            self.assertIn(f"--hash=sha256:{hashlib.sha256(built.read_bytes()).hexdigest()}", lock)
        self.assertTrue(lock.endswith(DEPENDENCIES))
        self.assertEqual(release_files.pins(lock), [f"stayawakebot=={VERSION}", "aiohttp==3.14.5",
                                                    "typing-extensions==4.16.0"])

    def test_a_security_release_is_named_only_by_its_own_section(self):
        self.assertFalse(release_files.is_security_release(CHANGELOG, VERSION))
        self.assertTrue(release_files.is_security_release(CHANGELOG, "0.17.5"))
        self.assertFalse(release_files.is_security_release(CHANGELOG, "9.9.9"))

    def test_a_wheel_no_client_can_place_stops_the_release(self):
        for tag in ("macosx_10_9_universal2", "linux_x86_64", "manylinux_2_28_s390x"):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    release_files.platform_of(tag)

    def test_two_wheels_for_one_platform_stop_the_release(self):
        _wheel(self.dist, "manylinux_2_17_x86_64")
        with self.assertRaises(ValueError):
            self._write()

    def test_a_wheel_of_another_version_stops_the_release(self):
        _wheel(self.dist, "win_arm64", version="0.17.7")
        with self.assertRaises(ValueError):
            self._write()

    def test_a_dependency_without_a_hash_stops_the_release(self):
        (self.tmp / "dependencies.lock").write_text(DEPENDENCIES + "certifi==2026.11.20\n")
        with self.assertRaises(ValueError):
            self._write()

    def test_a_requirement_not_pinned_to_one_version_is_refused(self):
        with self.assertRaises(ValueError):
            release_files.pins("aiohttp>=3 \\\n    --hash=sha256:aaaa\n")


if __name__ == "__main__":
    unittest.main()
