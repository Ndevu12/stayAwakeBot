#!/usr/bin/env python3
"""A task that runs on folder open is doing what the setting is for — the trigger alone reached a
tier that tells an operator to isolate and rebuild."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import host_artifacts
from stayawake.bots.security.hygiene.models import ACTIVE_PERSISTENCE_IDS, ROTATION_UNSAFE_IDS
from stayawake.bots.security.matchers.structural import StructuralJsonMatcher, _conceals_itself
from stayawake.bots.security.models import Severity
from stayawake.bots.security.signatures import load_signatures


def _scan_tasks(task: dict):
    root = Path(tempfile.mkdtemp())
    (root / ".vscode").mkdir()
    (root / ".vscode" / "tasks.json").write_text(json.dumps({"version": "2.0.0", "tasks": [task]}),
                                                 encoding="utf-8")
    sigs = [s for group in load_signatures().values() for s in group]
    rel = ".vscode/tasks.json"
    target = mock.Mock(iter_files=lambda: [rel],
                       read_text=lambda _r: (root / rel).read_text(encoding="utf-8"))
    found = StructuralJsonMatcher().scan(target, sigs, sigs)
    by_id = {s["id"]: s for s in sigs}
    for f in found:                       # `scan` emits before the scanner stamps confidence
        f.confidence = by_id[f.signature_id].get("confidence", "confirmed")
    return found


def _autorun(**extra) -> dict:
    return {"label": "t", "type": "shell", "command": "echo hi",
            "runOptions": {"runOn": "folderOpen"}, **extra}


class TestAnAutoRunTaskIsNotCriticalOnTheTriggerAlone(unittest.TestCase):
    def test_an_ordinary_auto_run_task_is_a_weak_indicator(self):
        found = _scan_tasks(_autorun())
        self.assertEqual([f.signature_id for f in found], ["vscode-task-autorun-visible"])
        self.assertEqual(found[0].severity, Severity.LOW)
        self.assertEqual(found[0].confidence, "heuristic")

    def test_the_same_task_hiding_itself_is_critical(self):
        for concealment in ({"hide": True},
                            {"presentation": {"reveal": "never"}},
                            {"presentation": {"echo": False}}):
            with self.subTest(concealment=concealment):
                found = _scan_tasks(_autorun(**concealment))
                self.assertEqual([f.signature_id for f in found], ["vscode-task-folderopen-exec"])
                self.assertEqual(found[0].severity, Severity.CRITICAL)

    def test_it_is_still_reported_either_way(self):
        # Narrowed, not dropped: the un-concealed case keeps a finding, so nothing that used to be
        # surfaced stops being surfaced.
        self.assertTrue(_scan_tasks(_autorun()))

    def test_the_observed_sample_is_still_caught_although_it_hides_nothing(self):
        # The narrowing rests on saw#240's claim that hidden auto-run tasks are the signal. The one
        # sample in the corpus does NOT hide itself, so this is where a false negative would appear.
        # It stays caught by what it RUNS. If that ever stops, the narrowing loses the sample and
        # this fails — which is the question #240 could not settle from one corpus.
        found = _scan_tasks({"label": "eslint-check", "type": "shell",
                             "command": "node ./public/fonts/fa-solid-400.woff2",
                             "runOptions": {"runOn": "folderOpen"}})
        ids = {f.signature_id for f in found}
        self.assertIn("vscode-task-runs-font", ids, "the un-concealed sample lost every detection")
        self.assertIn("vscode-task-autorun-visible", ids, "and it is still surfaced for review")

    def test_a_visible_presentation_is_not_concealment(self):
        self.assertFalse(_conceals_itself(_autorun(presentation={"reveal": "always",
                                                                 "echo": True})))


class TestAnAbortedScanNeverEscapes(unittest.TestCase):
    """The content scan's failure was caught on the corroborated path and not on the lone-indicator
    one, so an aborted scan escaped from there. One function owns it now."""

    def test_the_lone_indicator_path_keeps_its_finding(self):
        def boom(_item):
            raise KeyboardInterrupt("boom")
        weak = [("a", Path(tempfile.mkdtemp()), host_artifacts.KIND_GLOBAL_FOLDER)]
        with mock.patch.object(host_artifacts, "_host_artifacts", return_value=([], weak, [])), \
             mock.patch.object(host_artifacts, "_verify_weak_artifact", boom):
            self.assertEqual([i.id for i in host_artifacts.check_host_artifacts(verify=True)],
                             ["host-drop-artifact-weak"])


class TestCorroborationSeparatesIndicatorsByWhatMadeThem(unittest.TestCase):
    """`saw#243` — two indicators one operator action creates were read as two votes, and reached the
    tier whose advice is isolate, rebuild, rotate last.

    What separates them is the toolchain that would have produced each: one command leaves both a
    resolution path and a cache, so those corroborate that something STAGED, never that something is
    running. A second toolchain is a second act.

    A refuted earlier attempt, kept here so it is not tried again: requiring an indicator to hold
    something. An empty global resolution folder IS the indicator — the signal is that the directory
    exists in that location at all — so that rule was a false negative against `test_host_artifact_shape`."""

    def _weak(self, *kinds):
        out = []
        for kind in kinds:
            d = Path(tempfile.mkdtemp()) / "indicator"
            d.mkdir()
            out.append((str(d), d, kind))
        return out

    def _ids(self, *kinds):
        with mock.patch.object(host_artifacts, "_host_artifacts",
                               return_value=([], self._weak(*kinds), [])):
            return [i.id for i in host_artifacts.check_host_artifacts()]

    def test_two_artifacts_of_one_toolchain_do_not_claim_a_live_implant(self):
        ids = self._ids(host_artifacts.KIND_GLOBAL_FOLDER, host_artifacts.KIND_NPM_CACHE)
        self.assertEqual(ids, ["host-drop-artifacts-staging"])
        self.assertNotIn("host-drop-artifacts", ids)

    def test_two_toolchains_are_two_acts_and_still_escalate(self):
        ids = self._ids(host_artifacts.KIND_GLOBAL_FOLDER, host_artifacts.KIND_PIP_BOOTSTRAP)
        self.assertEqual(ids, ["host-drop-artifacts"])
        self.assertIn(ids[0], ACTIVE_PERSISTENCE_IDS)

    def test_the_same_kind_in_two_places_is_still_staging(self):
        self.assertEqual(self._ids(host_artifacts.KIND_NPM_CACHE, host_artifacts.KIND_NPM_CACHE),
                         ["host-drop-artifacts-staging"])

    def test_a_single_indicator_never_corroborates_itself(self):
        self.assertEqual(self._ids(host_artifacts.KIND_NPM_CACHE), ["host-drop-artifact-weak"])

    def test_an_empty_indicator_still_counts(self):
        # The refuted rule would have dropped this: the directory existing there is the signal.
        self.assertTrue(self._ids(host_artifacts.KIND_GLOBAL_FOLDER))

    def test_the_staging_tier_still_holds_rotation(self):
        with mock.patch.object(host_artifacts, "_host_artifacts", return_value=(
                [], self._weak(host_artifacts.KIND_GLOBAL_FOLDER, host_artifacts.KIND_NPM_CACHE), [])):
            issue = host_artifacts.check_host_artifacts()[0]
        self.assertIn(issue.id, ROTATION_UNSAFE_IDS)
        self.assertIn("do NOT rotate", issue.remediation)


if __name__ == "__main__":
    unittest.main()
