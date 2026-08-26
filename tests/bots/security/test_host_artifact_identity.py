#!/usr/bin/env python3
"""One directory reached under two names is one piece of evidence, not two.

Grading counted description strings, and the temp-root set deduped by name, so on any host where
`$TMPDIR` names the same directory as `/tmp` a single npm cache corroborated itself into
`host-drop-artifacts` — active persistence, exit 3, and "rebuild from a known-clean image".

Every directory here is real and every alias is a real symlink: a string stub would pass against
the counting rule this pins against.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import host_artifacts as h
from stayawake.bots.security.hygiene.models import (
    ACTIVE_PERSISTENCE_IDS, ROTATION_UNSAFE_IDS, ROTATION_UNSAFE_STAGING, rotation_safety)
from stayawake.utils.pathsafe import canonical_id, distinct

REAL_DISTINCT = h._distinct_dirs        # captured before any patch


class CanonicalIdentity(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_a_symlinked_directory_shares_its_target_identity(self):
        real = self.root / "real"; real.mkdir()
        alias = self.root / "alias"; alias.symlink_to(real)
        self.assertEqual(canonical_id(real), canonical_id(alias))
        self.assertEqual(distinct([real, alias]), 1)

    def test_the_probe_collapses_aliased_roots_before_probing_them(self):
        # Pinned separately from grading: artifact-level identity happens to cover this too, so a
        # revert here is invisible end-to-end — until an artifact that cannot be stat'd or
        # realpath'd falls open to "distinct" and corroborates itself under two root names.
        real = self.root / "real"; real.mkdir()
        alias = self.root / "alias"; alias.symlink_to(real)
        self.assertEqual([str(p) for p in h._distinct_dirs([real, alias])], [str(real)])

    def test_genuinely_different_directories_stay_distinct(self):
        a = self.root / "a"; a.mkdir()
        b = self.root / "b"; b.mkdir()
        self.assertEqual(distinct([a, b]), 2)

    def test_an_unresolvable_path_fails_open_to_distinct(self):
        # Collapsing on failure would stop a real directory being probed — a detection loss.
        self.assertEqual(distinct([self.root / "nope-a", self.root / "nope-b"]), 2)

    def test_a_zero_inode_falls_through_rather_than_collapsing(self):
        # Some FUSE / network mounts report st_ino 0; treating that as an identity would make every
        # such directory the same object.
        real = self.root / "real"; real.mkdir()
        other = self.root / "other"; other.mkdir()
        st = os.stat(real)

        class _Zero:
            st_dev, st_ino = st.st_dev, 0
        with mock.patch.object(h.os if hasattr(h, "os") else os, "stat", return_value=_Zero()):
            with mock.patch("stayawake.utils.pathsafe.os.stat", return_value=_Zero()):
                self.assertEqual(distinct([real, other]), 2)


class Grading(unittest.TestCase):
    """The acceptance criteria, exercised end to end through `check_host_artifacts`."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.real = self.root / "realtmp"; self.real.mkdir()
        self.alias = self.root / "aliastmp"; self.alias.symlink_to(self.real)
        self.other = self.root / "othertmp"; self.other.mkdir()
        self.home = self.root / "home"; self.home.mkdir()

    def _run(self, tmp_dirs, *, verify=False, global_folders=()):
        patches = [
            mock.patch.object(h, "_distinct_dirs", lambda paths: REAL_DISTINCT(tmp_dirs)),
            mock.patch.object(h.Path, "home", staticmethod(lambda: self.home)),
            mock.patch.object(h, "_global_folders", lambda: list(global_folders)),
            mock.patch.object(h, "_host_user_tag", lambda: None),
            mock.patch.object(h, "_sideloaded_python_dir", lambda: None),
            mock.patch.object(h, "_staged_secret_scanner", lambda d: None),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)
        issues = h.check_host_artifacts(verify=verify)
        return {i.id for i in issues}, issues

    def test_one_artifact_under_two_names_cannot_corroborate_itself(self):
        (self.real / ".npm").mkdir()
        ids, _ = self._run([self.real, self.alias])
        self.assertNotIn("host-drop-artifacts", ids)
        self.assertNotIn("host-drop-artifacts-staging", ids)
        self.assertEqual(ids, {"host-drop-artifact-weak"})
        self.assertFalse(ids & ROTATION_UNSAFE_IDS, "one npm cache must not gate rotation")

    def test_two_distinct_kinds_still_warn_and_gate(self):
        (self.real / ".npm").mkdir()
        (self.real / "get-pip.py").write_text("#")
        ids, _ = self._run([self.real])
        self.assertEqual(ids, {"host-drop-artifacts"})
        self.assertTrue(ids & ACTIVE_PERSISTENCE_IDS)
        self.assertTrue(ids & ROTATION_UNSAFE_IDS)

    def test_same_kind_in_two_real_directories_keeps_the_gate_without_claiming_persistence(self):
        (self.real / ".npm").mkdir()
        (self.other / ".npm").mkdir()
        ids, _ = self._run([self.real, self.other])
        self.assertEqual(ids, {"host-drop-artifacts-staging"})
        # The GATE is the no-downgrade invariant (exit 3 reads the id set). The verdict STRING is
        # its own value so the report does not announce persistence it has just said it cannot see.
        self.assertTrue(ids & ROTATION_UNSAFE_IDS, "no downgrade: rotation stays gated")
        self.assertEqual(rotation_safety(ids), ROTATION_UNSAFE_STAGING)
        self.assertFalse(ids & ACTIVE_PERSISTENCE_IDS, "staging must not claim a live implant")

    def test_a_symlinked_artifact_across_two_real_roots_still_corroborates(self):
        # Collapsing these would hand an attacker a way to switch the alarm off: drop once, symlink
        # a second name at it, and the corroboration disappears while both paths still resolve.
        # Aliasing a ROOT is a system fact; aliasing an ARTIFACT is somebody's deliberate act.
        (self.real / ".npm").mkdir()
        (self.other / ".npm").symlink_to(self.real / ".npm")
        ids, _ = self._run([self.real, self.other])
        self.assertEqual(ids, {"host-drop-artifacts-staging"})
        self.assertTrue(ids & ROTATION_UNSAFE_IDS)

    def test_the_lone_indicator_is_unchanged(self):
        (self.real / ".npm").mkdir()
        ids, _ = self._run([self.real])
        self.assertEqual(ids, {"host-drop-artifact-weak"})


class VerifyEscalatesOnly(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.a = self.root / "a"; self.a.mkdir()
        self.b = self.root / "b"; self.b.mkdir()
        self.home = self.root / "home"; self.home.mkdir()
        (self.a / ".npm").mkdir()
        (self.b / ".npm").mkdir()

    def _run(self, scan):
        patches = [
            mock.patch.object(h, "_distinct_dirs", lambda paths: REAL_DISTINCT([self.a, self.b])),
            mock.patch.object(h.Path, "home", staticmethod(lambda: self.home)),
            mock.patch.object(h, "_global_folders", lambda: []),
            mock.patch.object(h, "_host_user_tag", lambda: None),
            mock.patch.object(h, "_sideloaded_python_dir", lambda: None),
            mock.patch.object(h, "_staged_secret_scanner", lambda d: None),
            mock.patch.object(h, "_verify_weak_artifact", scan),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)
        return h.check_host_artifacts(verify=True)

    def test_a_clean_scan_cannot_lower_a_corroborated_finding(self):
        issues = self._run(lambda item: [])
        self.assertEqual({i.id for i in issues}, {"host-drop-artifacts-staging"})
        self.assertTrue({i.id for i in issues} & ROTATION_UNSAFE_IDS)

    def test_markers_in_the_second_location_still_escalate(self):
        seen = []

        def scan(item):
            seen.append(item[1])
            if len(seen) == 1:
                return []                       # first location clean — must not stop the walk
            return [h.HygieneIssue(id="host-artifact-content-infected", severity="warning",
                                   title="t", detail="d", remediation="r")]
        issues = self._run(scan)
        self.assertEqual({i.id for i in issues}, {"host-artifact-content-infected"})
        self.assertEqual(len(seen), 2, "a clean first location must not mask an infected second")

    def test_a_scan_that_raises_still_reports_what_the_probe_found(self):
        for exc in (ImportError, ValueError, RecursionError, KeyboardInterrupt):
            with self.subTest(exc=exc.__name__):
                self.doCleanups()
                self.setUp()

                def boom(item, _e=exc):
                    raise _e("boom")
                issues = self._run(boom)
                ids = {i.id for i in issues}
                self.assertEqual(ids, {"host-drop-artifacts-staging"})
                self.assertIn("could not complete", issues[0].detail)


if __name__ == "__main__":
    unittest.main()
