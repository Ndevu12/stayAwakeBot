#!/usr/bin/env python3
"""Prefilter gates + walk memoization (#1326): byte-identical speedups.

The gates skip expensive analysis only when a NECESSARY anchor is absent — so detection is unchanged.
These pin the necessity contract (the load-bearing zero-downgrade property) and that the walk-once
memo replays the same file list.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.taint import analyzer, flow, model
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions


class TestDecodeAnchorDerivation(unittest.TestCase):
    def test_anchors_derived_from_model(self):
        # One source of truth: adding a decode call to the taxonomy updates the gate automatically.
        expected = frozenset(n.split(".", 1)[0].lower() for n in model.DECODE_CALLS)
        self.assertEqual(analyzer._DECODE_ANCHORS, expected)
        self.assertEqual(analyzer._DECODE_ANCHORS, {"atob", "buffer"})  # today's taxonomy

    def test_every_decode_call_carries_an_anchor(self):
        # The necessity proof: each decode name, as it appears in source, contains one of the anchors
        # (lowercased) — so flow._DECODE can never match text that lacks every anchor.
        for name in model.DECODE_CALLS:
            low = name.lower()
            self.assertTrue(any(a in low for a in analyzer._DECODE_ANCHORS), name)


class TestDetectDropperGate(unittest.TestCase):
    # Known droppers spanning every arm — each MUST still be flagged, and each MUST carry an anchor.
    _DROPPERS = [
        "const r = execSync(Buffer.from('QQBB'*40,'base64'));",
        "import(atob('QQBBQQBBQQBB'));",
        "spawn('sh', ['-c', atob('QQBBQQBB')]);",
        "execSync('bash -c ' + Buffer.from('QQBB','base64'));",
    ]

    def test_known_droppers_still_detected_and_carry_anchor(self):
        for src in self._DROPPERS:
            self.assertIsNotNone(analyzer.detect_dropper(src), src)
            low = src.lower()
            self.assertTrue(any(a in low for a in analyzer._DECODE_ANCHORS), src)

    def test_gate_returns_none_only_when_no_anchor(self):
        # No decode anchor → the gate short-circuits to None (eval is caught elsewhere, not here).
        self.assertIsNone(analyzer.detect_dropper("eval(x); const y = 1; foo(bar);"))

    def test_gate_is_a_necessary_condition_not_a_verdict(self):
        # Anchor PRESENT but not a dropper → still None (the gate only lets the pipeline run; it never
        # fabricates a finding). A lone benign Buffer.from decode is not a dropper.
        self.assertIsNone(analyzer.detect_dropper("const jwt = Buffer.from(token, 'base64').toString();"))


class TestDynamicExecGate(unittest.TestCase):
    def test_tight_anchors_appear_in_their_regexes(self):
        # Drift guard: each anchor is a literal the corresponding always-on arm requires.
        self.assertIn("data:", flow._DATA_URI_IMPORT.pattern)
        self.assertIn("child_process", flow._REQUIRE_CP_DECODE.pattern)
        self.assertIn("shelljs", flow._REQUIRE_CP_DECODE.pattern)

    def test_tight_arms_still_detected(self):
        self.assertTrue(flow._has_corroborated_dynamic_exec(
            "import('data:text/javascript;base64,QQBBQQBB');"))
        self.assertTrue(flow._has_corroborated_dynamic_exec(
            "require('child_process').exec(atob('QQBBQQBB'));"))

    def test_no_anchor_no_tight_match(self):
        self.assertFalse(flow._has_corroborated_dynamic_exec("const x = import('./lazy.js');"))


class TestWalkMemoization(unittest.TestCase):
    def test_iter_files_walks_once_and_replays_identically(self):
        d = tempfile.mkdtemp(prefix="walk-memo-")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        for i in range(5):
            (Path(d) / f"f{i}.js").write_text("x")
        target = LocalRepoTarget(d, "t", ScanOptions())
        real_walk = os.walk
        calls = {"n": 0}

        def counting_walk(*a, **k):
            calls["n"] += 1
            return real_walk(*a, **k)

        with mock.patch("stayawake.bots.security.targets.base.os.walk", side_effect=counting_walk):
            first = list(target.iter_files())
            second = list(target.iter_files())
            third = list(target.iter_files())
        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(sorted(first), [f"f{i}.js" for i in range(5)])
        self.assertEqual(calls["n"], 1, "the tree must be walked exactly once, then replayed")

    def test_include_only_never_walks(self):
        target = LocalRepoTarget("/nonexistent", "t", ScanOptions(), include_only=("a.js", "b.js"))
        with mock.patch("stayawake.bots.security.targets.base.os.walk",
                        side_effect=AssertionError("should not walk when include_only is set")):
            self.assertEqual(list(target.iter_files()), ["a.js", "b.js"])


if __name__ == "__main__":
    unittest.main()
