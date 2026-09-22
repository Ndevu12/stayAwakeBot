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
        # plan/apply handles only the reliable STRUCTURAL actions (remove fonts, strip
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
        self.assertTrue(self.q.exists())            # originals preserved for rollback

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
        missing = type("F", (), {"remediation": "quarantine-file"})()
        self.assertFalse(remediation.is_auto_fixable(missing))

    def test_remove_residual_removes_and_backs_up(self):
        repo = Path(tempfile.mkdtemp())
        (repo / "evil.cjs").write_text("module.exports = sfL(0)\n", encoding="utf-8")
        q = remediation.rollback_path(repo)
        finding = type("F", (), {"path": "evil.cjs"})()
        done = remediation.remove_residual(repo, [finding], q)
        self.assertEqual([c.action for c in done], ["remove"])
        self.assertFalse((repo / "evil.cjs").exists())          # removed from the tree
        self.assertTrue((q / "evil.cjs").exists())              # backed up first

    def test_removal_does_not_remove_the_repository_root(self):
        repo = Path(tempfile.mkdtemp())
        keep = repo / "keep.txt"
        keep.write_text("x\n", encoding="utf-8")
        q = Path(tempfile.mkdtemp())
        applied = remediation.apply(repo, [remediation.Change("remove", ".", "x")], q)
        self.assertEqual(applied, [])
        self.assertTrue(keep.is_file())
        finding = type("F", (), {"path": ".", "remediation": "quarantine-file",
                                 "confidence": "confirmed", "description": "x"})()
        self.assertNotIn(".", {c.path for c in remediation.plan([finding])})

    def test_backup_does_not_follow_a_planted_destination(self):
        repo = Path(tempfile.mkdtemp())
        (repo / "payload.js").write_text("from-repo\n", encoding="utf-8")
        host = Path(tempfile.mkdtemp()) / "sink"
        host.write_text("host\n", encoding="utf-8")
        q = Path(tempfile.mkdtemp())
        (q / "payload.js").symlink_to(host)
        remediation.changes._backup(repo, "payload.js", q)
        self.assertEqual(host.read_text(encoding="utf-8"), "host\n")
        self.assertTrue((q / "payload.js").is_symlink())

    def test_backup_does_not_mkdir_through_a_linked_parent(self):
        repo = Path(tempfile.mkdtemp())
        payload = repo / "a" / "b" / "fonts"
        payload.mkdir(parents=True)
        (payload / "x.woff").write_text("x\n", encoding="utf-8")
        host = Path(tempfile.mkdtemp())
        q = Path(tempfile.mkdtemp())
        (q / "a").symlink_to(host)
        remediation.changes._backup(repo, "a/b/fonts", q)
        self.assertEqual(list(host.iterdir()), [])

    def test_backup_does_not_merge_into_a_planted_directory(self):
        repo = Path(tempfile.mkdtemp())
        src = repo / "payload"
        src.mkdir()
        (src / "sink.txt").write_text("from-repo\n", encoding="utf-8")
        host = Path(tempfile.mkdtemp()) / "sink.txt"
        host.write_text("host\n", encoding="utf-8")
        q = Path(tempfile.mkdtemp())
        dest = q / "payload"
        dest.mkdir()
        (dest / "sink.txt").symlink_to(host)
        remediation.changes._backup(repo, "payload", q)
        self.assertEqual(host.read_text(encoding="utf-8"), "host\n")

    def test_strip_does_not_write_a_hardlinked_file(self):
        repo = Path(tempfile.mkdtemp())
        gi = repo / ".gitignore"
        gi.write_text("temp_auto_push.bat\nkeep\n", encoding="utf-8")
        host = Path(tempfile.mkdtemp()) / "victim"
        os.link(gi, host)
        applied = remediation.apply(
            repo, [remediation.Change("strip-gitignore", ".gitignore")],
            Path(tempfile.mkdtemp()))
        self.assertEqual(applied, [])
        self.assertEqual(host.read_text(encoding="utf-8"), "temp_auto_push.bat\nkeep\n")

    def test_backup_does_not_write_outside_the_rollback_store(self):
        base = Path(tempfile.mkdtemp())
        repo = base / "repo"
        repo.mkdir()
        srcdir = base / "payload"
        srcdir.mkdir()
        (srcdir / "inner.txt").write_text("from-repo\n", encoding="utf-8")
        (base / "srcfile").write_text("from-repo\n", encoding="utf-8")
        q = base / "q" / "nested"
        q.mkdir(parents=True)
        remediation.changes._backup(repo, "../payload", q)
        remediation.changes._backup(repo, "../srcfile", q)
        self.assertFalse((base / "q" / "payload").exists())
        self.assertFalse((base / "q" / "srcfile").exists())

    def test_backup_does_not_mkdir_through_a_bouncing_path(self):
        base = Path(tempfile.mkdtemp())
        q = base / "probe" / "q"
        q.mkdir(parents=True)
        root = Path(tempfile.mkdtemp()) / "probe" / "q"
        root.mkdir(parents=True)
        marker = "EVIL_SAW_R7"
        rel = f"x/../../{marker}/../q/file"
        (root / "x").mkdir()
        (root.parent / marker).mkdir()
        (root / "file").write_text("from-repo\n", encoding="utf-8")
        remediation.changes._backup(root, rel, q)
        self.assertFalse((base / "probe" / marker).exists())
        self.assertFalse((q / "file").exists())

    def test_backup_does_not_follow_a_dangling_destination(self):
        repo = Path(tempfile.mkdtemp())
        (repo / "payload.js").write_text("from-repo\n", encoding="utf-8")
        host = Path(tempfile.mkdtemp()) / "sink"
        q = Path(tempfile.mkdtemp())
        (q / "payload.js").symlink_to(host)
        remediation.changes._backup(repo, "payload.js", q)
        self.assertFalse(host.exists())
        self.assertTrue((q / "payload.js").is_symlink())

    def test_writeback_does_not_write_a_hardlinked_file(self):
        from stayawake.bots.security.remediation import writeback
        repo = Path(tempfile.mkdtemp())
        src = repo / "code.js"
        src.write_text("payload\n", encoding="utf-8")
        host = Path(tempfile.mkdtemp()) / "victim"
        os.link(src, host)
        ok = writeback._backup_write_verify(
            repo, "code.js", "stripped\n", Path(tempfile.mkdtemp()), None)
        self.assertFalse(ok)
        self.assertEqual(host.read_text(encoding="utf-8"), "payload\n")

    def test_removal_does_not_follow_a_linked_directory(self):
        repo = Path(tempfile.mkdtemp())
        host = Path(tempfile.mkdtemp())
        payload = host / "payload.js"
        payload.write_text("x\n", encoding="utf-8")
        (repo / "escdir").symlink_to(host)
        q = remediation.rollback_path(repo)
        finding = type("F", (), {"path": "escdir/payload.js"})()
        done = remediation.remove_residual(repo, [finding], q)
        self.assertEqual(done, [])
        self.assertTrue(payload.is_file())
        applied = remediation.apply(
            repo, [remediation.Change("remove", "escdir/payload.js")], q)
        self.assertEqual(applied, [])
        self.assertTrue(payload.is_file())

    def test_backup_skips_symlink(self):
        repo = Path(tempfile.mkdtemp())
        secret = repo / "secret.txt"
        secret.write_text("top-secret\n", encoding="utf-8")
        link = repo / "link.txt"
        link.symlink_to(secret)
        q = Path(tempfile.mkdtemp())
        remediation.changes._backup(repo, "link.txt", q)
        # the symlink target's contents must not be copied into the rollback store
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

    def test_removal_of_a_symlinked_dir_unlinks_not_rmtrees(self):
        # apply() removal of a symlink-to-directory must unlink the link, never rmtree THROUGH it.
        repo = Path(tempfile.mkdtemp())
        outside = Path(tempfile.mkdtemp()); (outside / "keep.txt").write_text("keep\n")
        (repo / "linkdir").symlink_to(outside, target_is_directory=True)
        remediation.apply(repo, [remediation.Change("remove", "linkdir", "x")],
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


class TestActionScopeMatchesEvidence(unittest.TestCase):
    """saw#288 — a removal covers the file the evidence named, never its whole directory."""

    GENUINE_WOFF2 = b"wOF2" + bytes(400)
    GENUINE_TTF = b"\x00\x01\x00\x00" + bytes(400)
    GENUINE_LICENSE = "SIL Open Font License 1.1\nCopyright the font authors.\n"
    CAMOUFLAGE_README = ("# Fonts Directory\n"
                         "This directory contains custom fonts for the Blockchain Explorer.\n"
                         "Required: BlockchainFont-Regular, TechMono-Regular.\n")
    PAYLOAD_WOFF2 = "function f(){ var a = 1; return a }\n"

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp()) / "repo"
        self.fonts = self.repo / "public" / "fonts"
        self.fonts.mkdir(parents=True)
        self.q = self.repo / ".malware-quarantine"
        (self.fonts / "README.md").write_text(self.CAMOUFLAGE_README, encoding="utf-8")
        (self.fonts / "Inter.woff2").write_bytes(self.GENUINE_WOFF2)
        (self.fonts / "NotoSans.ttf").write_bytes(self.GENUINE_TTF)
        (self.fonts / "OFL.txt").write_text(self.GENUINE_LICENSE, encoding="utf-8")

    def _findings(self):
        return scan_target(LocalRepoTarget(self.repo, "t", ScanOptions()), SIGS, []).findings

    def test_camouflage_readme_and_payload_go_but_genuine_fonts_and_the_dir_stay(self):
        """The flagged README and the JS-carrying woff2 are removed; the genuine third-party
        fonts beside them, and the fonts directory itself, survive."""
        (self.fonts / "fa-solid-400.woff2").write_text(self.PAYLOAD_WOFF2, encoding="utf-8")
        plan = remediation.plan(self._findings())
        self.assertNotIn("public/fonts", {c.path for c in plan})
        self.assertEqual({"public/fonts/README.md", "public/fonts/fa-solid-400.woff2"},
                         {c.path for c in plan})
        remediation.apply(self.repo, plan, self.q)
        self.assertFalse((self.fonts / "README.md").exists())
        self.assertFalse((self.fonts / "fa-solid-400.woff2").exists())
        self.assertTrue(self.fonts.is_dir())
        self.assertEqual((self.fonts / "Inter.woff2").read_bytes(), self.GENUINE_WOFF2)
        self.assertEqual((self.fonts / "NotoSans.ttf").read_bytes(), self.GENUINE_TTF)
        self.assertEqual((self.fonts / "OFL.txt").read_text(encoding="utf-8"), self.GENUINE_LICENSE)

    def test_a_filename_alone_is_suspicious_not_infected(self):
        """A file matched only by its name (bytes never read) is a weak signal — it is reported for
        review, not asserted as an infection. A real payload of that name is caught by its content."""
        import tempfile
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.signatures import load_signatures
        from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
        from stayawake.bots.security.models import HEURISTIC, CONFIRMED

        def scan_one(name, content):
            root = Path(tempfile.mkdtemp()); d = root / "public" / "fonts"; d.mkdir(parents=True)
            f = d / name
            f.write_bytes(content) if isinstance(content, bytes) else f.write_text(content)
            return scan_target(LocalRepoTarget(root, str(root), ScanOptions()), load_signatures())

        res = scan_one("fa-solid-400.woff2", self.GENUINE_WOFF2)
        name_only = next(f for f in res.findings if f.signature_id == "fake-font-fa-solid-400")
        self.assertEqual(name_only.confidence, HEURISTIC)
        self.assertEqual(res.verdict, "suspicious")

        res2 = scan_one("fa-solid-400.woff2",
                        "global['_V']=function(x){return x};require('child_process').exec('x');\n" + "// " * 40)
        self.assertTrue(res2.infected)
        self.assertTrue(any(f.confidence == CONFIRMED for f in res2.findings))

    def test_a_filename_only_font_is_reported_but_never_auto_removed(self):
        """A fa-solid-400.woff2 with real font magic trips only the filename signature (its bytes
        were never read); it stays reported yet fix never deletes it, while the camouflage README —
        read by content — is removed."""
        (self.fonts / "fa-solid-400.woff2").write_bytes(self.GENUINE_WOFF2)
        findings = self._findings()
        ids = {f.signature_id for f in findings}
        self.assertIn("fake-font-fa-solid-400", ids)
        self.assertNotIn("fake-font-text-woff", ids)
        remediation.apply(self.repo, remediation.plan(findings), self.q)
        self.assertTrue((self.fonts / "fa-solid-400.woff2").exists())
        self.assertEqual((self.fonts / "fa-solid-400.woff2").read_bytes(), self.GENUINE_WOFF2)
        self.assertFalse((self.fonts / "README.md").exists())


if __name__ == "__main__":
    unittest.main()
