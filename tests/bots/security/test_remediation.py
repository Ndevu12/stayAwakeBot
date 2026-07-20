#!/usr/bin/env python3
"""Remediation engine: planning + applying makes an infected tree clean, idempotently."""
from __future__ import annotations

import shutil
import os
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

    def test_structural_apply_cleans_nonloader_findings(self):
        # plan/apply handles only the reliable STRUCTURAL actions (quarantine fonts, strip
        # exact .gitignore lines, drop autorun JSON keys). Categories with remediation=manual (or
        # heuristic confidence) are NOT surgically edited and remain after a bare plan/apply on this
        # (non-git) fixture: code-loader routes to git recovery; npm-lifecycle hooks aren't safely
        # strippable (the manifest may be legit); agent-autorun (.claude hooks) defers to review; and
        # camouflage here is the whitespace-concealment tell in postcss.config.mjs (a hidden payload
        # is reviewed/recovered by hand, not auto-stripped).
        before = self._findings()
        self.assertTrue(before, "fixture should start infected")
        applied = remediation.apply(self.repo, remediation.plan(before), self.q)
        self.assertTrue(applied, "should apply the structural changes")
        remaining = {f.category for f in self._findings()}
        self.assertEqual(remaining, {"code-loader", "npm-lifecycle", "agent-autorun", "camouflage"},
                         f"only manual-remediation categories should remain: {remaining}")
        self.assertTrue(self.q.exists())            # originals preserved in quarantine

    def test_idempotent(self):
        remediation.apply(self.repo, remediation.plan(self._findings()), self.q)
        # second pass plans nothing: structural findings are gone and code-loader never
        # produces a plan() change (it routes to recovery, not surgical edit).
        self.assertEqual(remediation.plan(self._findings()), [], "second pass should be a no-op")


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
    def test_is_auto_fixable(self):
        # Only the structure-safe actions are "auto-fixable" via plan/apply. Code-loader
        # (remediation `recover`) is NOT — it goes through git recovery, never a surgical edit.
        good = type("F", (), {"remediation": "strip-gitignore-markers", "confidence": "confirmed"})()
        code_loader = type("F", (), {"remediation": "recover", "confidence": "confirmed"})()
        manual = type("F", (), {"remediation": "manual"})()
        self.assertTrue(remediation.is_auto_fixable(good))
        self.assertFalse(remediation.is_auto_fixable(code_loader))
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

    def test_strip_refuses_write_through_a_planted_symlink(self):
        # #1218: a committed symlink named settings.json pointing at an OUT-OF-TREE sink must NOT be
        # written through by apply()'s strip path — the sink stays intact and the change is skipped.
        repo = Path(tempfile.mkdtemp())
        sink = Path(tempfile.mkdtemp()) / "victim.bashrc"
        sink.write_text("SAFE ORIGINAL\n", encoding="utf-8")
        (repo / ".vscode").mkdir()
        (repo / ".vscode" / "settings.json").symlink_to(sink)
        applied = remediation.apply(
            repo, [remediation.Change("strip-settings", ".vscode/settings.json", "autorun")],
            Path(tempfile.mkdtemp()))
        self.assertEqual(applied, [])                            # refused — never written through
        self.assertEqual(sink.read_text(), "SAFE ORIGINAL\n")   # the out-of-tree sink is untouched

    def test_quarantine_of_a_symlinked_dir_unlinks_not_rmtrees(self):
        # apply() quarantine of a symlink-to-directory must unlink the link, never rmtree THROUGH it.
        repo = Path(tempfile.mkdtemp())
        outside = Path(tempfile.mkdtemp()); (outside / "keep.txt").write_text("keep\n")
        (repo / "linkdir").symlink_to(outside, target_is_directory=True)
        remediation.apply(repo, [remediation.Change("quarantine", "linkdir", "x")],
                          Path(tempfile.mkdtemp()))
        self.assertFalse((repo / "linkdir").exists())           # the planted link is removed
        self.assertTrue((outside / "keep.txt").exists())        # its target dir is untouched


class TestPathSafe(unittest.TestCase):
    """The shared SymJacking write-through guard (#1218)."""
    def test_refuses_symlink_and_escape_allows_benign(self):
        from stayawake.utils.pathsafe import is_safe_write_target
        root = Path(tempfile.mkdtemp())
        (root / "real.json").write_text("{}")
        (root / "link").symlink_to(Path(tempfile.mkdtemp()) / "sink")     # symlinked leaf
        os.symlink(tempfile.mkdtemp(), root / "escdir")                   # symlinked ancestor dir
        self.assertFalse(is_safe_write_target(root / "link", root))
        self.assertFalse(is_safe_write_target(root / "escdir" / "x.json", root))
        self.assertFalse(is_safe_write_target(root / ".." / "x", root))  # .. escape
        self.assertTrue(is_safe_write_target(root / "real.json", root))  # benign existing
        self.assertTrue(is_safe_write_target(root / "new.json", root))   # benign new file


if __name__ == "__main__":
    unittest.main()
