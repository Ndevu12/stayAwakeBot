#!/usr/bin/env python3
"""Remediation engine: planning + applying makes an infected tree clean, idempotently."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path


from stayawake.bots.security.signatures import load_signatures      # noqa: E402
from stayawake.bots.security.scanner import scan_target             # noqa: E402
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions  # noqa: E402
from stayawake.bots.security import remediation                     # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "infected"
SIGS = load_signatures()


class TestRemediation(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp()) / "repo"
        shutil.copytree(FIX, self.repo)
        self.q = self.repo / ".malware-quarantine"

    def _findings(self):
        return scan_target(LocalRepoTarget(self.repo, "t", ScanOptions()), SIGS, []).findings

    def test_apply_makes_tree_clean(self):
        before = self._findings()
        self.assertTrue(before, "fixture should start infected")
        applied = remediation.apply(self.repo, remediation.plan(before), self.q)
        self.assertTrue(applied, "should apply changes")
        remaining = {f.signature_id for f in self._findings()}
        self.assertEqual(remaining, set(), f"still infected after remediation: {remaining}")
        # originals preserved in quarantine
        self.assertTrue(self.q.exists())

    def test_idempotent(self):
        remediation.apply(self.repo, remediation.plan(self._findings()), self.q)
        self.assertEqual(remediation.plan(self._findings()), [], "second pass should be a no-op")

    def test_strip_payload_keeps_legit_config(self):
        text = 'const config = { plugins: [] };\nexport default config;PAYLOAD_JUNK_HERE\n'
        out = remediation.strip_payload_text(text)
        self.assertIn("export default config;", out)
        self.assertNotIn("PAYLOAD_JUNK_HERE", out)


class TestEnsureIgnored(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.gi = self.repo / ".gitignore"

    def _lines(self):
        return self.gi.read_text(encoding="utf-8").splitlines()

    def test_creates_gitignore_when_absent(self):
        self.assertTrue(remediation.ensure_ignored(self.repo))
        self.assertIn(".malware-quarantine/", self._lines())

    def test_appends_only_missing_patterns(self):
        self.gi.write_text("node_modules/\n", encoding="utf-8")
        self.assertTrue(remediation.ensure_ignored(self.repo))
        lines = self._lines()
        self.assertEqual(lines.count(".malware-quarantine/"), 1, "must not duplicate")
        self.assertIn("node_modules/", lines)

    def test_idempotent_no_change_when_present(self):
        remediation.ensure_ignored(self.repo)
        self.assertFalse(remediation.ensure_ignored(self.repo), "second call should be a no-op")

    def test_refuses_symlinked_gitignore(self):
        outside = self.repo / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        self.gi.symlink_to(outside)
        self.assertFalse(remediation.ensure_ignored(self.repo))   # must not follow the symlink
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")


class TestStripAndResidual(unittest.TestCase):
    def test_strip_removes_loader_above_export(self):
        # A1: loader prepended ABOVE export default must be removed, not preserved.
        txt = "var _$_abcd = sfL(0)\nString.fromCharCode(127)\nexport default {a:1};\n"
        out = remediation.strip_payload_text(txt)
        self.assertNotIn("sfL(", out)
        self.assertNotIn("fromCharCode", out)
        self.assertIn("export default", out)

    def test_is_auto_fixable(self):
        good = type("F", (), {"remediation": "strip-appended-payload"})()
        manual = type("F", (), {"remediation": "manual"})()
        self.assertTrue(remediation.is_auto_fixable(good))
        self.assertFalse(remediation.is_auto_fixable(manual))

    def test_quarantine_residual_removes_and_backs_up(self):
        repo = Path(tempfile.mkdtemp())
        (repo / "evil.cjs").write_text("module.exports = sfL(0)\n", encoding="utf-8")
        q = remediation.quarantine_path(repo)
        finding = type("F", (), {"path": "evil.cjs"})()
        done = remediation.quarantine_residual(repo, [finding], q)
        self.assertEqual([c.action for c in done], ["quarantine"])
        self.assertFalse((repo / "evil.cjs").exists())          # removed from the tree
        self.assertTrue((q / "evil.cjs").exists())              # backed up first

    def test_backup_skips_symlink(self):
        repo = Path(tempfile.mkdtemp())
        secret = repo / "secret.txt"
        secret.write_text("top-secret\n", encoding="utf-8")
        link = repo / "link.txt"
        link.symlink_to(secret)
        q = Path(tempfile.mkdtemp())
        remediation._backup(repo, "link.txt", q)
        # the symlink target's contents must not be copied into quarantine
        self.assertFalse((q / "link.txt").exists())


if __name__ == "__main__":
    unittest.main()
