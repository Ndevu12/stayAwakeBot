#!/usr/bin/env python3
"""Guards for the scanner-pin tooling in .github/scripts/pin_tools.py.

The tooling stops the worm-guard gate's pinned scanner (`sentinel-ref`) from silently drifting
behind the detection engine. A bug in it fails OPEN (drift sails through) or CLOSED (blocks
unrelated PRs), so the fiddly boundaries are pinned here, not only in CI. The module is imported by
path (it lives outside the package) and its pure decision functions are exercised directly:
  - TestExtractPin  — the pin extraction (40-hex only; a floating `main` yields None).
  - TestFreshness   — the in-band PR gate (engine changed ⇒ pin bumped, or deferred).
  - TestSynced      — the in-band sync gate: every pin carrier holds the SAME SHA.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / ".github" / "scripts" / "pin_tools.py"

_spec = importlib.util.spec_from_file_location("pin_tools", SCRIPT)
pt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pt)

SHA_A = "050f3b6e4557629493177b5eea39867e31ed4173"
SHA_B = "5e28e6548d2275ee7cec3a0e141a9b53f6544bcb"


class TestExtractPin(unittest.TestCase):
    def test_extracts_40hex_sha(self):
        self.assertEqual(pt.extract_pin(f"          sentinel-ref: {SHA_A}   # merge of #1170"), SHA_A)

    def test_floating_ref_yields_none(self):
        self.assertIsNone(pt.extract_pin("          sentinel-ref: main"))

    def test_no_pin_yields_none(self):
        self.assertIsNone(pt.extract_pin("nothing to see here"))

    def test_pin_files_lists_both_carriers(self):
        # PIN_FILES is the single source for "which files pin the scanner" — both the worm-guard gate
        # and the release self-scan must be in it, or `synced` can't gate one.
        self.assertIn(".github/workflows/worm-guard.yml", pt.PIN_FILES)
        self.assertIn(".github/workflows/release.yml", pt.PIN_FILES)


# An ADDED (+) pin bump hunk vs. the pin present only as unchanged CONTEXT vs. a reset to floating.
PIN_BUMP_DIFF = (
    " jobs:\n"
    f"-          sentinel-ref: {SHA_B}\n"
    f"+          sentinel-ref: {SHA_A}\n"
)
PIN_CONTEXT_DIFF = f"           sentinel-ref: {SHA_B}\n"        # leading space, not '+'
PIN_FLOATING_DIFF = f"-          sentinel-ref: {SHA_B}\n+          sentinel-ref: main\n"

ENGINE = "src/stayawake/bots/security/matchers/heuristic.py\n"
GUARD = ".github/workflows/worm-guard.yml\n"


class TestFreshness(unittest.TestCase):
    def _code(self, changed: str, diff: str, deferred: bool = False) -> int:
        return pt.freshness(changed, diff, deferred)[0]

    def test_engine_changed_without_bump_fails(self):
        self.assertEqual(self._code(ENGINE, ""), 1)

    def test_engine_changed_with_bump_passes(self):
        self.assertEqual(self._code(ENGINE + GUARD, PIN_BUMP_DIFF), 0)

    def test_engine_changed_deferred_passes(self):
        self.assertEqual(self._code("src/stayawake/bots/security/scanner.py\n", "", deferred=True), 0)

    def test_no_engine_change_passes(self):
        self.assertEqual(self._code("README.md\ndocs/x.md\nsrc/stayawake/cli.py\n", ""), 0)

    def test_sibling_paths_do_not_trigger(self):
        # tests/ under a 'security' dir, and a sibling 'security_helpers' — neither is the engine.
        self.assertEqual(self._code("tests/bots/security/test_heuristic.py\n"
                                    "src/stayawake/bots/security_helpers/util.py\n", ""), 0)

    def test_pin_line_as_context_is_not_a_bump(self):
        self.assertEqual(self._code("src/stayawake/bots/security/scanner.py\n", PIN_CONTEXT_DIFF), 1)

    def test_floating_ref_is_not_a_valid_bump(self):
        self.assertEqual(self._code("src/stayawake/bots/security/scanner.py\n", PIN_FLOATING_DIFF), 1)


class TestSynced(unittest.TestCase):
    def test_matching_pins_pass(self):
        code, _ = pt.pins_synced({"a.yml": SHA_A, "b.yml": SHA_A})
        self.assertEqual(code, 0)

    def test_mismatched_pins_fail(self):
        code, msgs = pt.pins_synced({"a.yml": SHA_A, "b.yml": SHA_B})
        self.assertEqual(code, 1)
        self.assertTrue(any("mismatch" in m for m in msgs))

    def test_floating_or_missing_pin_fails(self):
        self.assertEqual(pt.pins_synced({"a.yml": SHA_A, "b.yml": None})[0], 1)

    def test_single_carrier_is_trivially_synced(self):
        self.assertEqual(pt.pins_synced({"a.yml": SHA_A})[0], 0)


if __name__ == "__main__":
    unittest.main()
