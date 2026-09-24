#!/usr/bin/env python3
"""What a run does to the checkout the operator is standing in."""
from __future__ import annotations

import unittest
from pathlib import Path

from stayawake.bots.security.remediation import live
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.scratchroot import OwnTempRoot

LOADER = "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n"
GENUINE_FONT = b"wOFF\x00\x01\x00\x00genuine third-party font bytes\n"


class _Checkout(OwnTempRoot):
    def setUp(self):
        super().setUp()
        self.root = (self.tmp / "project").resolve()
        (self.root / "public" / "fonts").mkdir(parents=True)
        (self.root / "src").mkdir()
        (self.root / "src" / "index.js").write_text("export const greet = (n) => n;\n")

    def _findings(self):
        return scan_target(LocalRepoTarget(self.root, "p", ScanOptions()),
                           load_signatures(), []).findings

    def _clean(self):
        return live.clean(self.root, self._findings(), load_signatures(), [], ScanOptions())


class TestThePayloadLeavesTheCheckout(_Checkout):
    def test_the_condemned_file_is_gone_from_the_checkout(self):
        payload = self.root / "public" / "fonts" / "text.woff"
        payload.write_text(LOADER)
        result = self._clean()
        self.assertFalse(payload.exists())
        self.assertIn("public/fonts/text.woff", result.removed)

    def test_no_copy_of_it_is_kept_anywhere_under_the_checkout(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        self._clean()
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn("fromCharCode", path.read_text(errors="replace"), str(path))

    def test_the_operators_other_files_are_untouched(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        self._clean()
        self.assertEqual("export const greet = (n) => n;\n",
                         (self.root / "src" / "index.js").read_text())

    def test_a_checkout_with_nothing_condemned_is_left_alone(self):
        before = sorted(str(p) for p in self.root.rglob("*"))
        result = self._clean()
        self.assertEqual([], result.removed)
        self.assertEqual(before, sorted(str(p) for p in self.root.rglob("*")))


class TestItNeverRemovesWhatItDidNotRead(_Checkout):
    """Check what a run does to a path it cannot read as a file."""

    def _condemn(self, path):
        from stayawake.bots.security.models import Finding, Severity
        return [Finding("x", "c", Severity.CRITICAL, path, "d",
                        remediation="remove-file", confidence="confirmed")]

    def test_a_directory_at_a_condemned_path_survives(self):
        here = self.root / "public" / "fonts" / "text.woff"
        here.mkdir(parents=True)
        (here / "theirs.md").write_text("mine\n")
        result = live.clean(self.root, self._condemn("public/fonts/text.woff"),
                            load_signatures(), [], ScanOptions())
        self.assertTrue((here / "theirs.md").exists())
        self.assertEqual([], result.removed)

    def test_a_run_that_met_one_is_not_complete(self):
        (self.root / "public" / "fonts" / "text.woff").mkdir(parents=True)
        result = live.clean(self.root, self._condemn("public/fonts/text.woff"),
                            load_signatures(), [], ScanOptions())
        self.assertFalse(result.complete)

    def test_a_payload_file_is_still_removed(self):
        payload = self.root / "public" / "fonts" / "text.woff"
        payload.write_text(LOADER)
        result = live.clean(self.root, self._findings(), load_signatures(), [], ScanOptions())
        self.assertFalse(payload.exists())
        self.assertEqual(["public/fonts/text.woff"], result.removed)


class TestItSaysWhatItCouldNotDo(_Checkout):
    def test_a_clean_run_is_complete(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        findings = self._findings()
        result = live.clean(self.root, findings, load_signatures(), [], ScanOptions())
        self.assertTrue(result.complete)
        self.assertEqual([], result.unread)

    def test_a_run_it_could_not_finish_is_not_complete(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        findings = self._findings()
        (self.root / "public" / "fonts" / "text.woff").unlink()
        result = live.clean(self.root, findings, load_signatures(), [], ScanOptions())
        self.assertFalse(result.complete)
        self.assertIn("not clean", result.note())

    def test_what_it_did_not_remove_is_named(self):
        payload = self.root / "public" / "fonts" / "text.woff"
        payload.write_text(LOADER)
        findings = self._findings()
        payload.write_bytes(GENUINE_FONT)
        result = live.clean(self.root, findings, load_signatures(), [], ScanOptions())
        self.assertTrue(payload.exists())
        self.assertIn("public/fonts/text.woff", result.left)


if __name__ == "__main__":
    unittest.main()
