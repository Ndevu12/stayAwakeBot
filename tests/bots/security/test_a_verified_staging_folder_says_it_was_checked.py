#!/usr/bin/env python3
"""After `saw audit --verify` reads every staging place in full and finds them clean, the staging finding
says what the scan found and no longer sends you back to `--verify`; it keeps its grade, its rotation hold
and its "do NOT rotate any credential yet", names no place, and anything short of a full clean read keeps
the advice it had."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import host_artifacts as h
from stayawake.bots.security.hygiene.models import (ROTATION_SAFE_PENDING_CHECK, ROTATION_UNSAFE_STAGING,
                                                    HygieneIssue, rotation_safety)

_HOLD = "do NOT rotate any credential yet"
_ASKS_FOR_VERIFY = "Run `saw audit --verify`, and do NOT rotate any credential yet."


class _AHome(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="staging-home-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        patches = [
            mock.patch.dict(os.environ, {
                "HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config"),
                "XDG_CACHE_HOME": str(self.home / ".cache"),
                "NPM_CONFIG_PREFIX": str(self.home / "no-prefix"), "PREFIX": str(self.home / "no-prefix")}),
            mock.patch.object(h, "_temp_dirs", lambda: []),
            mock.patch.object(h, "_npm_prefix_roots", lambda: []),
            mock.patch.object(h, "_host_user_tag", lambda: None),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _kit(self):
        kit = self.home / ".node_modules"
        (kit / "node_modules").mkdir(parents=True)
        (kit / "package.json").write_text(json.dumps({"dependencies": {"axios": "^1.18.1",
                                                                       "socket.io-client": "^4.8.3"}}))
        for name in ("axios", "socket.io-client"):
            package = kit / "node_modules" / name
            package.mkdir()
            (package / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0", "main": "index.js"}))
            (package / "index.js").write_text("module.exports = function () {};\n")

    def _staging(self):
        self._kit()
        (self.home / ".node_libraries").mkdir(mode=0o700)

    def _only(self, verify: bool) -> HygieneIssue:
        issues = h.check_host_artifacts(verify=verify)
        self.assertEqual(len(issues), 1, [i.id for i in issues])
        return issues[0]


class TestAStagingFindingScannedCleanSaysSo(_AHome):
    def test_it_says_what_the_scan_found_and_no_longer_asks_for_verify(self):
        self._staging()
        issue = self._only(verify=True)
        self.assertEqual((issue.id, issue.severity), ("host-drop-artifacts-staging", "warning"))
        self.assertIn("A scan of what they hold found no worm markers.", issue.detail)
        self.assertNotIn("--verify", issue.remediation)
        self.assertIn(_HOLD, issue.remediation)
        self.assertIn("`saw harden`", issue.remediation)

    def test_the_rotation_hold_is_unchanged(self):
        self._staging()
        self.assertEqual(rotation_safety({self._only(verify=True).id}), ROTATION_UNSAFE_STAGING)

    def test_it_names_no_place(self):
        self._staging()
        issue = self._only(verify=True)
        for text in (issue.title, issue.detail, issue.remediation):
            for place in (str(self.home), ".node_modules", ".node_libraries"):
                self.assertNotIn(place, text)

    def test_the_report_still_holds_rotation_wherever_it_did(self):
        from stayawake.bots.security import hygiene
        self._staging()
        report = " ".join(hygiene.render([self._only(verify=True)], width=100).split())
        self.assertIn("Rotation safety: UNSAFE", report)
        self.assertIn("Do NOT rotate credentials yet", report)
        self.assertIn(_HOLD, report)

    def test_without_verify_it_still_asks_for_it(self):
        self._staging()
        self.assertEqual(self._only(verify=False).remediation, _ASKS_FOR_VERIFY)

    def test_the_report_keeps_its_shape(self):
        clean = h._FoundCleanByAScan(id="i", severity="info", title="t", detail="d", remediation="r")
        self.assertEqual(set(clean.to_dict()), {f.name for f in fields(HygieneIssue)})


def _report(issues, **kwargs) -> str:
    from stayawake.bots.security import hygiene
    return " ".join(hygiene.render(issues, width=100, **kwargs).split())


class TestTheReportAfterVerifyNoLongerSendsYouBack(_AHome):
    def test_after_a_clean_verify_the_report_holds_rotation_and_offers_no_verify(self):
        self._staging()
        report = _report([self._only(verify=True)], content_scanned=True)
        self.assertNotIn("saw audit --verify", report)
        for kept in ("Rotation safety: UNSAFE", "Do NOT rotate credentials yet", _HOLD,
                     "Rebuild the host only if a scan or your own inspection finds payload code."):
            self.assertIn(kept, report)

    def test_the_default_report_still_offers_verify(self):
        self._staging()
        report = _report([self._only(verify=False)])
        self.assertIn("`saw audit --verify` content-scans them for payload code.", report)
        for kept in ("Rotation safety: UNSAFE", "Do NOT rotate credentials yet", _ASKS_FOR_VERIFY):
            self.assertIn(kept, report)

    def test_a_place_left_outside_a_control_reads_the_same_way(self):
        left = HygieneIssue(id="host-drop-artifact-outside-a-control", severity="warning", title="t",
                            detail="d", remediation="Run `saw harden`, and do not rotate any credential yet.")
        scanned, offered = _report([left], content_scanned=True), _report([left])
        self.assertNotIn("saw audit --verify", scanned)
        self.assertIn("`saw audit --verify` content-scans it for payload code.", offered)
        for report in (scanned, offered):
            self.assertIn("Do NOT rotate credentials yet", report)
            self.assertIn("Rotation safety: UNSAFE", report)


class TestTheAuditCommandSaysWhenItScanned(unittest.TestCase):
    def _rendered_with(self, verify: bool) -> dict:
        import argparse
        from stayawake.cli.commands import audit
        seen = {}

        def rendering(issues, **kwargs):
            seen.update(kwargs)
            return ""
        args = argparse.Namespace(repo=None, branch="main", fail=False, verify_artifacts=verify,
                                  no_stream=True)
        with mock.patch.object(audit.hygiene, "audit_checks", return_value=[]), \
                mock.patch.object(audit.hygiene, "render", side_effect=rendering), \
                mock.patch.object(audit.auth, "resolve_token", return_value=(None, None)):
            audit.run(args)
        return seen

    def test_verify_is_passed_to_the_report(self):
        self.assertTrue(self._rendered_with(True)["content_scanned"])
        self.assertFalse(self._rendered_with(False)["content_scanned"])


class TestAPlaceTheScanCouldNotReadInFullIsSaid(_AHome):
    def _verdict(self, **fields):
        verdict = {"has_markers": False, "markers": [], "files": 3, "scanned_clean": False,
                   "too_large": False, "partial": False, "unread": []}
        verdict.update(fields)
        return mock.Mock(**verdict)

    def _report_with_second(self, second) -> str:
        self._staging()
        verdicts = [self._verdict(scanned_clean=True), second]

        def scanning(path):
            answer = verdicts.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        with mock.patch("stayawake.bots.security.verify.verify_dir", side_effect=scanning):
            return _report([self._only(verify=True)], content_scanned=True)

    def test_a_clean_place_beside_one_the_scan_could_not_finish_says_so(self):
        for name, second in (("too large", self._verdict(too_large=True)),
                             ("read in part", self._verdict(partial=True)),
                             ("read in part, named",
                              self._verdict(partial=True, unread=["a nested archive"])),
                             ("the scan raised", RuntimeError("boom"))):
            with self.subTest(second=name):
                self.doCleanups()
                self.setUp()
                report = self._report_with_second(second)
                self.assertIn("could not finish reading every place", report)
                self.assertNotIn("found no worm markers", report)
                self.assertNotIn("saw audit --verify", report)
                for kept in ("Rotation safety: UNSAFE", "Do NOT rotate credentials yet", _HOLD):
                    self.assertIn(kept, report)

    def test_a_place_outside_a_control_the_scan_could_not_finish_says_so(self):
        issue = h._outside_a_control_not_read_in_full_issue(["a place"])
        self.assertIn("could not finish reading it", issue.detail)
        self.assertNotIn("--verify", issue.remediation)
        self.assertIn("do not rotate any credential yet", issue.remediation)


class TestAnythingShortOfAFullCleanReadKeepsItsAdvice(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="staging-mixed-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.a, self.b, self.home = self.root / "a", self.root / "b", self.root / "home"
        for folder in (self.a, self.b, self.home):
            folder.mkdir()
        for folder in (self.a, self.b):
            (folder / ".npm").mkdir()
            (folder / ".npm" / "staged.tgz").write_text("x")

    def _run(self, scans, roots=None):
        answers = iter(scans)
        patches = [
            mock.patch.object(h, "_distinct_dirs", lambda paths: list(roots or [self.a, self.b])),
            mock.patch.object(h.Path, "home", staticmethod(lambda: self.home)),
            mock.patch.object(h, "_global_folders", lambda: []),
            mock.patch.object(h, "_host_user_tag", lambda: None),
            mock.patch.object(h, "_sideloaded_python_dir", lambda *_a, **_k: None),
            mock.patch.object(h, "_staged_secret_scanner", lambda *_a, **_k: None),
            mock.patch.object(h, "_verify_weak_artifact", lambda item: self._answer(next(answers))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return h.check_host_artifacts(verify=True)

    @staticmethod
    def _answer(answer):
        if isinstance(answer, Exception):
            raise answer
        return answer

    def test_a_scan_that_fails_on_one_place_still_reads_the_others(self):
        infected = [HygieneIssue(id="host-artifact-content-infected", severity="warning", title="t",
                                 detail="d", remediation="r")]
        self.assertEqual(self._run([RuntimeError("boom"), infected])[0].id, "host-artifact-content-infected")

    def test_a_place_left_outside_a_control_says_the_scan_could_not_finish(self):
        with mock.patch.object(h.hostdenial, "held_by_us", lambda location: True), \
                mock.patch.object(h, "_global_folders", lambda: [self.home / ".node_modules"]):
            issue = self._run_with_globals([self._weak()])[0]
        self.assertEqual(issue.id, "host-drop-artifact-outside-a-control")
        self.assertIn("could not finish reading it", issue.detail)

    def _run_with_globals(self, scans):
        answers = iter(scans)
        patches = [
            mock.patch.object(h, "_distinct_dirs", lambda paths: [self.a]),
            mock.patch.object(h.Path, "home", staticmethod(lambda: self.home)),
            mock.patch.object(h, "_host_user_tag", lambda: None),
            mock.patch.object(h, "_sideloaded_python_dir", lambda *_a, **_k: None),
            mock.patch.object(h, "_staged_secret_scanner", lambda *_a, **_k: None),
            mock.patch.object(h, "_verify_weak_artifact", lambda item: self._answer(next(answers))),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return h.check_host_artifacts(verify=True)

    @staticmethod
    def _clean():
        return [h._FoundCleanByAScan(id="host-drop-artifact-weak", severity="info", title="t", detail="d",
                                     remediation="r")]

    @staticmethod
    def _weak():
        return [HygieneIssue(id="host-drop-artifact-weak", severity="info", title="t", detail="d", remediation="r")]

    def test_every_place_clean_says_so(self):
        issues = self._run([self._clean(), self._clean()])
        self.assertNotIn("--verify", issues[0].remediation)

    def test_a_place_the_scan_could_not_finish_says_so_and_does_not_ask_for_verify_again(self):
        for second in (self._weak(), None, []):
            with self.subTest(second=second):
                self.doCleanups()
                self.setUp()
                issue = self._run([self._clean(), second])[0]
                self.assertEqual(issue.id, "host-drop-artifacts-staging")
                self.assertIn("could not finish reading every place", issue.detail)
                self.assertNotIn("found no worm markers", issue.detail)
                self.assertNotIn("--verify", issue.remediation)
                self.assertIn(_HOLD, issue.remediation)

    def test_markers_in_one_place_still_escalate(self):
        infected = [HygieneIssue(id="host-artifact-content-infected", severity="warning", title="t", detail="d",
                                 remediation="r")]
        issues = self._run([self._clean(), infected])
        self.assertEqual(issues[0].id, "host-artifact-content-infected")

    def test_a_finding_of_live_files_never_reads_as_cleared(self):
        (self.a / "get-pip.py").write_text("#")
        issues = self._run([self._clean()] * 3, roots=[self.a])
        self.assertEqual(issues[0].id, "host-drop-artifacts")
        self.assertNotIn("found no worm markers", issues[0].detail)
        self.assertIn("rotate credentials LAST", issues[0].remediation)


class TestALoneKitReadsAsBefore(_AHome):
    def test_without_verify(self):
        self._kit()
        issue = self._only(verify=False)
        self.assertEqual((issue.id, issue.remediation), ("host-drop-artifact-weak", "Run `saw audit --verify`."))
        self.assertEqual(rotation_safety({issue.id}), ROTATION_SAFE_PENDING_CHECK)

    def test_with_verify(self):
        self._kit()
        issue = self._only(verify=True)
        self.assertEqual(issue.id, "host-drop-artifact-weak")
        self.assertIn("A scan found no markers.", issue.detail)
        self.assertEqual(rotation_safety({issue.id}), ROTATION_SAFE_PENDING_CHECK)


if __name__ == "__main__":
    unittest.main()
