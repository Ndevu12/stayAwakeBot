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
from stayawake.bots.security.hygiene.models import ACTIVE_PERSISTENCE_IDS
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
        with mock.patch.object(host_artifacts, "_host_artifacts", return_value=([], weak)), \
             mock.patch.object(host_artifacts, "_verify_weak_artifact", boom):
            self.assertEqual([i.id for i in host_artifacts.check_host_artifacts(verify=True)],
                             ["host-drop-artifact-weak"])


class TestCorroborationStillCountsOccurrences(unittest.TestCase):
    """CHARACTERISATION — this locks in behaviour that is still wrong, so a fix has to change it
    deliberately rather than by accident, and so the evidence is not lost.

    `saw#243`: two weak indicators one operator action creates are read as corroboration and reach
    the tier whose advice is isolate, rebuild, rotate last.

    An attempted fix — require an indicator to hold something before it corroborates — is WITHDRAWN.
    It is a false negative against a shipped contract: an empty global resolution folder is itself
    the indicator, because the signal is that the directory exists in that location at all, not what
    is in it (`test_host_artifact_shape`). Whatever closes #243 has to separate indicators by their
    ORIGIN, and emptiness is not that. Recorded so the next attempt does not repeat it."""

    def _weak(self, *kinds):
        import tempfile
        out = []
        for kind in kinds:
            d = Path(tempfile.mkdtemp()) / "indicator"
            d.mkdir()
            out.append((str(d), d, kind))
        return out

    def test_two_empty_indicators_of_different_kinds_reach_the_active_tier(self):
        weak = self._weak(host_artifacts.KIND_GLOBAL_FOLDER, host_artifacts.KIND_NPM_CACHE)
        with mock.patch.object(host_artifacts, "_host_artifacts", return_value=([], weak)):
            issues = host_artifacts.check_host_artifacts()
        self.assertEqual([i.id for i in issues], ["host-drop-artifacts"])
        self.assertIn(issues[0].id, ACTIVE_PERSISTENCE_IDS)   # <- saw#243: not yet independent

    def test_one_kind_in_two_places_is_staging_and_that_part_is_correct(self):
        weak = self._weak(host_artifacts.KIND_GLOBAL_FOLDER, host_artifacts.KIND_GLOBAL_FOLDER)
        with mock.patch.object(host_artifacts, "_host_artifacts", return_value=([], weak)):
            self.assertEqual([i.id for i in host_artifacts.check_host_artifacts()],
                             ["host-drop-artifacts-staging"])

    def test_a_single_indicator_never_corroborates_itself(self):
        weak = self._weak(host_artifacts.KIND_GLOBAL_FOLDER)
        with mock.patch.object(host_artifacts, "_host_artifacts", return_value=([], weak)):
            self.assertEqual([i.id for i in host_artifacts.check_host_artifacts()],
                             ["host-drop-artifact-weak"])

    def test_the_withdrawn_rule_would_have_dropped_a_real_indicator(self):
        # The evidence that killed it, kept executable: an empty global resolution folder alongside
        # a second kind must still reach a warning. Requiring content made this weak.
        weak = self._weak(host_artifacts.KIND_GLOBAL_FOLDER, host_artifacts.KIND_PIP_BOOTSTRAP)
        with mock.patch.object(host_artifacts, "_host_artifacts", return_value=([], weak)):
            self.assertEqual([i.severity for i in host_artifacts.check_host_artifacts()], ["warning"])


if __name__ == "__main__":
    unittest.main()
