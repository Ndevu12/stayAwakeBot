#!/usr/bin/env python3
"""A project script that prepends a bare `node <file> &&` bootstrap before its real command.

This family makes its payload run on ordinary work by prefixing `node init &&` (or `node api &&`)
to `dev`/`build`/`start`, so opening the project and running it fires a top-level bootstrap. The
carrier file is already caught when its bytes match a loader fingerprint; this is the run-time
delivery signal, which still fires when a future carrier is packed in a way no fingerprint matches.
It is SUSPICIOUS, not INFECTED: a bare extensionless `node X &&` prepend is unusual but not proof.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import SUSPICIOUS, CLEAN
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()
_ID = "run-script-bootstrap-prepend"


def _scan_pkg(scripts):
    d = Path(tempfile.mkdtemp())
    (d / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts}), encoding="utf-8")
    return scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, [])


class TestRunScriptBootstrapPrepend(unittest.TestCase):
    def test_a_bare_bootstrap_prepended_to_dev_is_suspicious(self):
        for key in ("dev", "build", "start", "serve"):
            with self.subTest(key=key):
                r = _scan_pkg({key: "node init && vite"})
                self.assertIn(_ID, {f.signature_id for f in r.findings})
                self.assertEqual(r.verdict, SUSPICIOUS)   # heuristic, never a false "infected"

    def test_a_prepend_mid_command_is_seen(self):
        r = _scan_pkg({"dev": "cross-env NODE_ENV=dev && node api && next dev"})
        self.assertIn(_ID, {f.signature_id for f in r.findings})

    def test_running_a_normal_entry_point_is_clean(self):
        # `node server` with no chained bootstrap is an ordinary start command.
        r = _scan_pkg({"start": "node server"})
        self.assertNotIn(_ID, {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, CLEAN)

    def test_a_pathed_or_extensioned_codegen_step_is_clean(self):
        # Legit "run codegen then build" uses a real file path/extension, not a bare bootstrap.
        for cmd in ("node build.js && tsc", "node scripts/gen.js && vite", "node . && nodemon"):
            with self.subTest(cmd=cmd):
                r = _scan_pkg({"build": cmd})
                self.assertNotIn(_ID, {f.signature_id for f in r.findings})

    def test_a_plain_dev_command_is_clean(self):
        r = _scan_pkg({"dev": "vite", "build": "tsc && vite build"})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)


if __name__ == "__main__":
    unittest.main()
