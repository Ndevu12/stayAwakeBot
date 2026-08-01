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
from subprocess import CompletedProcess
from unittest import mock

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


class TestDrift(unittest.TestCase):
    """The out-of-band drift backstop's git/gh glue (#1293) — the pure functions are covered above,
    but `drift()` itself was untested, and a silent regression there fails OPEN (drift sails through).
    `_run` and the pin/issue lookups are mocked so no real git/gh runs."""

    @staticmethod
    def _cp(rc=0, out="", err=""):
        return CompletedProcess(args=[], returncode=rc, stdout=out, stderr=err)

    def _drift(self, *, pin=SHA_A, existing=None, diff_rc=1, names_out="a.py\nb.py\n"):
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            if cmd[:3] == ["git", "diff", "--quiet"]:
                return self._cp(rc=diff_rc, err="fatal: bad object" if diff_rc not in (0, 1) else "")
            if cmd[:3] == ["git", "diff", "--name-only"]:
                return self._cp(out=names_out)
            if cmd[:2] == ["git", "rev-parse"]:
                return self._cp(out="abc1234\n")
            return self._cp(out="")            # gh issue create/comment/close
        with mock.patch.object(pt, "extract_pin_file", return_value=pin), \
             mock.patch.object(pt, "_find_drift_issue", return_value=existing), \
             mock.patch.object(pt, "_run", side_effect=fake_run):
            rc = pt.drift()
        return rc, calls

    def test_unreadable_pin_fails_closed(self):
        rc, _ = self._drift(pin=None)
        self.assertEqual(rc, 1)

    def test_git_diff_error_fails_closed(self):
        # returncode NOT in (0, 1) is a real git error — it must return 1 (fail closed), never be
        # mistaken for "returncode 0 = no drift" (which would fail OPEN). This is the branch #1293
        # flagged as untested; the backstop silently passing on a git error is the exact hazard.
        rc, calls = self._drift(diff_rc=128)
        self.assertEqual(rc, 1)
        self.assertFalse(any("create" in c for c in calls))    # no issue churn on a hard error

    def test_no_drift_returns_zero(self):
        rc, _ = self._drift(diff_rc=0)
        self.assertEqual(rc, 0)

    def test_no_drift_closes_existing_issue(self):
        rc, calls = self._drift(diff_rc=0, existing="42")
        self.assertEqual(rc, 0)
        self.assertTrue(any(c[:3] == ["gh", "issue", "close"] for c in calls))

    def test_drift_comments_on_existing_issue(self):
        rc, calls = self._drift(diff_rc=1, existing="7")
        self.assertEqual(rc, 0)
        self.assertTrue(any(c[:3] == ["gh", "issue", "comment"] for c in calls))

    def test_drift_creates_issue_with_per_line_bullets(self):
        # A changed path CONTAINING A SPACE must be ONE bullet — the splitlines()-vs-split() fix
        # (#1293). With the old split() it would break into "dir/a" + "file.py" (two bullets).
        rc, calls = self._drift(diff_rc=1, existing=None, names_out="dir/a file.py\nb.py\n")
        self.assertEqual(rc, 0)
        create = next(c for c in calls if c[:3] == ["gh", "issue", "create"])
        body = create[create.index("--body") + 1]
        self.assertIn("- dir/a file.py", body)                 # one bullet, space preserved
        self.assertIn("- b.py", body)


if __name__ == "__main__":
    unittest.main()
