#!/usr/bin/env python3
"""Removing a known-malicious dependency from the manifest that declares it."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.dependencies.remediation import MALICIOUS, VULNERABLE
from stayawake.bots.security.pr.fix import _malicious_names
from stayawake.bots.security.remediation import manifest

MANIFEST = '''{
  "name": "app",
  "version": "1.0.0",
  "scripts": {
    "build": "tsc"
  },
  "dependencies": {
    "left-pad": "^1.3.0",
    "evil-pkg": "1.2.3"
  },
  "devDependencies": {
    "evil-pkg": "1.2.3",
    "jest": "^29.0.0"
  }
}
'''


def _repo(text: str = MANIFEST) -> Path:
    root = Path(tempfile.mkdtemp(prefix="saw-manifest-"))
    (root / "package.json").write_text(text, encoding="utf-8")
    return root


class TestTheEditIsSurgical(unittest.TestCase):
    """Check what the edit changes and what it leaves."""

    def test_it_removes_the_package_from_every_field(self):
        out = manifest.drop_from_manifest(MANIFEST, {"evil-pkg"})
        data = json.loads(out)
        self.assertNotIn("evil-pkg", data["dependencies"])
        self.assertNotIn("evil-pkg", data["devDependencies"])

    def test_it_keeps_every_other_dependency(self):
        data = json.loads(manifest.drop_from_manifest(MANIFEST, {"evil-pkg"}))
        self.assertEqual("^1.3.0", data["dependencies"]["left-pad"])
        self.assertEqual("^29.0.0", data["devDependencies"]["jest"])
        self.assertEqual("tsc", data["scripts"]["build"])

    def test_it_does_not_reformat_the_rest_of_the_file(self):
        out = manifest.drop_from_manifest(MANIFEST, {"evil-pkg"})
        kept = [l.rstrip(",") for l in MANIFEST.splitlines() if "evil-pkg" not in l]
        self.assertEqual(kept, [l.rstrip(",") for l in out.splitlines()])

    def test_it_closes_the_object_the_last_entry_left(self):
        out = manifest.drop_from_manifest(MANIFEST, {"evil-pkg"})
        self.assertIn('"left-pad": "^1.3.0"\n', out)
        json.loads(out)

    def test_nothing_to_remove_changes_nothing(self):
        self.assertIsNone(manifest.drop_from_manifest(MANIFEST, {"not-here"}))

    def test_an_empty_name_set_changes_nothing(self):
        self.assertEqual([], manifest.drop_dependencies(_repo(), set()))


class TestItFailsClosed(unittest.TestCase):
    """Check what a manifest saw cannot rewrite exactly produces."""

    def test_unparseable_text_is_left_alone(self):
        self.assertIsNone(manifest.drop_from_manifest("{not json", {"evil-pkg"}))

    def test_a_non_object_manifest_is_left_alone(self):
        self.assertIsNone(manifest.drop_from_manifest("[1, 2, 3]", {"evil-pkg"}))

    def test_a_name_used_as_a_key_elsewhere_does_not_corrupt_the_file(self):
        text = ('{\n  "scripts": {\n    "evil-pkg": "echo hi"\n  },\n'
                '  "dependencies": {\n    "evil-pkg": "1.2.3"\n  }\n}\n')
        out = manifest.drop_from_manifest(text, {"evil-pkg"})
        self.assertIsNone(out)

    def test_a_manifest_it_cannot_rewrite_is_not_written(self):
        root = _repo('{\n  "scripts": {\n    "evil-pkg": "echo hi"\n  },\n'
                     '  "dependencies": {\n    "evil-pkg": "1.2.3"\n  }\n}\n')
        before = (root / "package.json").read_text()
        self.assertEqual([], manifest.drop_dependencies(root, {"evil-pkg"}))
        self.assertEqual(before, (root / "package.json").read_text())

    def test_a_symlinked_manifest_is_not_followed(self):
        root = Path(tempfile.mkdtemp(prefix="saw-manifest-"))
        outside = Path(tempfile.mkdtemp(prefix="saw-outside-")) / "package.json"
        outside.write_text(MANIFEST, encoding="utf-8")
        (root / "package.json").symlink_to(outside)
        self.assertEqual([], manifest.drop_dependencies(root, {"evil-pkg"}))
        self.assertIn("evil-pkg", outside.read_text())


class TestItWritesTheRepository(unittest.TestCase):
    def test_it_rewrites_a_nested_manifest_too(self):
        root = _repo()
        nested = root / "packages" / "web"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(MANIFEST, encoding="utf-8")
        done = manifest.drop_dependencies(root, {"evil-pkg"})
        self.assertEqual(["package.json", "packages/web/package.json"], done)

    def test_it_does_not_walk_into_an_installed_tree(self):
        root = _repo()
        vendored = root / "node_modules" / "left-pad"
        vendored.mkdir(parents=True)
        (vendored / "package.json").write_text(MANIFEST, encoding="utf-8")
        self.assertEqual(["package.json"], manifest.drop_dependencies(root, {"evil-pkg"}))
        self.assertIn("evil-pkg", (vendored / "package.json").read_text())


class TestOnlyKnownMaliciousIsDropped(unittest.TestCase):
    """Check which findings name a package for removal."""

    def _finding(self, name: str, state: str) -> Finding:
        return Finding("sig", "supply-chain-dep", Severity.CRITICAL, "package.json", "d",
                       dependency_state=state, package=f"{name}@1.0.0", package_name=name)

    def test_a_malicious_package_is_named(self):
        self.assertEqual({"evil-pkg"}, _malicious_names([self._finding("evil-pkg", MALICIOUS)]))

    def test_a_vulnerable_package_is_not_named(self):
        self.assertEqual(set(), _malicious_names([self._finding("lodash", VULNERABLE)]))

    def test_a_finding_with_no_package_is_not_named(self):
        bare = Finding("sig", "c", Severity.LOW, "p", "d", dependency_state=MALICIOUS)
        self.assertEqual(set(), _malicious_names([bare]))

    def test_only_the_malicious_one_is_dropped_from_the_manifest(self):
        root = _repo()
        manifest.drop_dependencies(root, _malicious_names([
            self._finding("evil-pkg", MALICIOUS), self._finding("left-pad", VULNERABLE)]))
        data = json.loads((root / "package.json").read_text())
        self.assertNotIn("evil-pkg", data["dependencies"])
        self.assertIn("left-pad", data["dependencies"])


if __name__ == "__main__":
    unittest.main()
