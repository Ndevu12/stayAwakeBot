#!/usr/bin/env python3
"""`--verify` must COUNT what it could not read, and never let a clean read reassure.

Measured, one payload both ways: found in a `.tar` and a stored `.zip`, MISSED in a `.tgz` — so
coverage was a function of whether the attacker compressed the drop. Counted, not a boolean: one
`.pyc` used to take a whole tree from certifiable to "partial" (100% -> 46.7% on a site-packages).
"""
from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.verify import (_UNREAD_ARCHIVE, _UNREAD_ESCAPING,
                                            verify_dir)

_UNREAD = _UNREAD_ARCHIVE


def _confirmed_payload() -> bytes:
    """Triggers a CONFIRMED loader signature, assembled from split tokens so this file carries no
    contiguous IoC literal for the self-scan to flag."""
    cc, run = "from" + "CharCode", "ev" + "al"
    return f"const x = String.{cc}(127) + String.{cc}(127); {run}(x);".encode()


class ArchiveVerifyCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sigs = load_signatures()

    def _tree(self) -> Path:
        d = Path(tempfile.mkdtemp())
        (d / "package.json").write_text('{"name":"x","version":"1.0.0"}', encoding="utf-8")
        return d

    def _verify(self, d: Path):
        return verify_dir(d, signatures=self.sigs)


class TestAnArchiveIsNeverReportedAsScannedClean(ArchiveVerifyCase):
    def test_a_compressed_tarball_hiding_the_payload_is_not_clean(self):
        d = self._tree()
        payload = _confirmed_payload()
        with tarfile.open(d / "pkg.tgz", "w:gz") as tf:
            entry = tarfile.TarInfo("package/index.js")
            entry.size = len(payload)
            tf.addfile(entry, io.BytesIO(payload))
        verdict = self._verify(d)
        self.assertFalse(verdict.scanned_clean, "claimed clean over bytes it never decompressed")
        self.assertIn(_UNREAD, verdict.unread)

    def test_a_deflated_zip_is_not_clean(self):
        d = self._tree()
        with zipfile.ZipFile(d / "pkg.zip", "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("package/index.js", _confirmed_payload())
        self.assertFalse(self._verify(d).scanned_clean)

    def test_an_empty_archive_with_no_payload_is_still_not_clean(self):
        # The rule is about what was READ, not about what happened to be in it — an archive we did
        # not open cannot be said to be clean whatever it holds.
        d = self._tree()
        with tarfile.open(d / "empty.tgz", "w:gz"):
            pass
        self.assertFalse(self._verify(d).scanned_clean)

    def test_renaming_the_archive_cannot_buy_reassurance(self):
        # `.dat` alone was one variant shallow — a SOURCE extension short-circuits the coverage
        # classifier. What holds regardless is the report: no name makes the folder look safer,
        # because a clean read is never rendered as reassurance.
        from stayawake.bots.security.hygiene import host_artifacts
        payload = _confirmed_payload()
        for name in ("blob.dat", "stage.json", "bundle.map", "pkg.tgz"):
            with self.subTest(name=name):
                d = self._tree()
                with tarfile.open(d / name, "w:gz") as tf:
                    entry = tarfile.TarInfo("package/index.js")
                    entry.size = len(payload)
                    tf.addfile(entry, io.BytesIO(payload))
                issues = host_artifacts._verify_weak_artifact(("a node module tree", d))
                self.assertEqual(["host-drop-artifact-weak"], [i.id for i in issues])
                self.assertIn("does not clear it", " ".join(i.detail for i in issues))


class TestTheReportNamesArchivesAsUnread(ArchiveVerifyCase):
    def test_the_shortfall_is_named(self):
        d = self._tree()
        with tarfile.open(d / "pkg.tgz", "w:gz"):
            pass
        self.assertIn(_UNREAD, self._verify(d).unread)

    def test_the_named_cause_is_the_real_one(self):
        # The render site used to state an oversize file or an escaping symlink whatever the cause,
        # so an archive-bearing tree was explained by two things that had not happened.
        d = self._tree()
        with tarfile.open(d / "pkg.tgz", "w:gz"):
            pass
        unread = self._verify(d).unread
        self.assertNotIn(_UNREAD_ESCAPING, unread)
        self.assertNotIn("a file too large to read in full, or one that could not be read", unread)

    def test_the_finding_tells_the_operator_archives_went_unread(self):
        from stayawake.bots.security.hygiene import host_artifacts
        d = self._tree()
        with tarfile.open(d / "pkg.tgz", "w:gz"):
            pass
        issues = host_artifacts._verify_weak_artifact(("a node module tree", d))
        self.assertEqual(["host-drop-artifact-weak"], [i.id for i in issues])
        self.assertIn(_UNREAD, issues[0].detail)


class TestNoVerdictMovesDownward(ArchiveVerifyCase):
    """Marking archives unread may only withhold reassurance — never weaken an alarm, and never
    withdraw the all-clear from a tree that really was read."""

    def test_a_confirmed_marker_still_wins_over_an_archive_in_the_same_tree(self):
        d = self._tree()
        (d / "index.js").write_bytes(_confirmed_payload())
        with tarfile.open(d / "pkg.tgz", "w:gz"):
            pass
        verdict = self._verify(d)
        self.assertEqual(["loader-fromcharcode-127"], verdict.markers)
        self.assertTrue(verdict.has_markers)

    def test_an_uncompressed_archive_whose_bytes_matched_still_reports_the_marker(self):
        # A `.tar` is greppable by luck, so it used to match. It is still reported as a marker —
        # classifying it unread must not silence a hit we already had.
        d = self._tree()
        payload = _confirmed_payload()
        with tarfile.open(d / "pkg.tar", "w") as tf:
            entry = tarfile.TarInfo("package/index.js")
            entry.size = len(payload)
            tf.addfile(entry, io.BytesIO(payload))
        self.assertEqual(["loader-fromcharcode-127"], self._verify(d).markers)

    def test_an_ordinary_tree_is_still_read_without_complaint(self):
        d = self._tree()
        (d / "index.js").write_text("module.exports = function (a, b) { return a + b; };\n",
                                    encoding="utf-8")
        v = self._verify(d)
        self.assertTrue(v.scanned_clean)
        self.assertEqual([], v.unread)


if __name__ == "__main__":
    unittest.main()
