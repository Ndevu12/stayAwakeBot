#!/usr/bin/env python3
"""Guards for the scanner-pin tooling under .github/scripts/.

These scripts stop the worm-guard gate's pinned scanner (`sentinel-ref`) from silently drifting
behind the detection engine. Both build on the shared _pin_lib.sh (single source of the engine
subtree + pin token), so a bug there — or in the in-band freshness decision — fails OPEN (drift
sails through) or CLOSED (blocks unrelated PRs). The scripts are deliberately GitHub-free (diff
files / a file path + one env var in, exit code / stdout out) so the logic and its fiddly
boundaries are pinned here instead of only in CI:
  - TestPinLib       — the shared extraction (40-hex only; floating `main` rejected).
  - TestPinFreshness — the in-band PR gate (check_pin_freshness.sh).
  - TestPinsSynced   — the in-band sync gate (check_pins_synced.sh): both pin copies must agree.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / ".github" / "scripts"
SCRIPT = SCRIPTS / "check_pin_freshness.sh"
SCRIPT_SYNC = SCRIPTS / "check_pins_synced.sh"
PIN_LIB = SCRIPTS / "_pin_lib.sh"


class TestPinLib(unittest.TestCase):
    """The single source of truth both enforcement paths share."""

    def _extract(self, content: str) -> str:
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "worm-guard.yml"
            f.write_text(content)
            r = subprocess.run(
                ["bash", "-c", f'source "{PIN_LIB}"; extract_pin "{f}"'],
                capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
            self.assertEqual(r.returncode, 0, r.stderr)
            return r.stdout.strip()

    def test_extracts_40hex_sha(self):
        sha = "050f3b6e4557629493177b5eea39867e31ed4173"
        self.assertEqual(self._extract(f"          sentinel-ref: {sha}   # merge of #1170\n"), sha)

    def test_floating_ref_yields_no_pin(self):
        self.assertEqual(self._extract("          sentinel-ref: main\n"), "")

    def test_constants_are_the_expected_single_source(self):
        r = subprocess.run(
            ["bash", "-c",
             f'source "{PIN_LIB}"; printf "%s|%s" "$PIN_ENGINE_SUBTREE" "$PIN_GUARD_FILE"'],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(r.stdout.strip(),
                         "src/stayawake/bots/security|.github/workflows/worm-guard.yml", r.stderr)

    def test_double_source_is_safe(self):
        # The include guard must let a script source the lib twice without a readonly error.
        r = subprocess.run(
            ["bash", "-c", f'source "{PIN_LIB}"; source "{PIN_LIB}"; echo ok'],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok", r.stdout)

    def test_pin_files_set_lists_every_carrier(self):
        # PIN_FILES is the single source for "which files pin the scanner" — both the worm-guard
        # gate and the release self-scan must be in it, or check_pins_synced.sh can't gate one.
        r = subprocess.run(
            ["bash", "-c", f'source "{PIN_LIB}"; printf "%s\\n" "${{PIN_FILES[@]}}"'],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(r.returncode, 0, r.stderr)
        listed = r.stdout.split()
        self.assertIn(".github/workflows/worm-guard.yml", listed)
        self.assertIn(".github/workflows/release.yml", listed)

# A real +sentinel-ref bump hunk (added line, 40-char SHA), as it appears in `gh pr diff`.
PIN_BUMP_DIFF = (
    " jobs:\n"
    "-          sentinel-ref: 5e28e6548d2275ee7cec3a0e141a9b53f6544bcb\n"
    "+          sentinel-ref: 050f3b6e4557629493177b5eea39867e31ed4173\n"
)
# The pin line present only as unchanged CONTEXT (leading space, not '+') — NOT a bump.
PIN_CONTEXT_DIFF = "           sentinel-ref: 5e28e6548d2275ee7cec3a0e141a9b53f6544bcb\n"
# A reset to a floating ref — changed, but no 40-hex SHA, so it must NOT count as a valid bump.
PIN_FLOATING_DIFF = (
    "-          sentinel-ref: 5e28e6548d2275ee7cec3a0e141a9b53f6544bcb\n"
    "+          sentinel-ref: main\n"
)


class TestPinFreshness(unittest.TestCase):
    def _run(self, changed: str, diff: str, deferred: bool = False):
        with tempfile.TemporaryDirectory() as d:
            cf = Path(d) / "changed.txt"
            df = Path(d) / "pr.diff"
            cf.write_text(changed)
            df.write_text(diff)
            return subprocess.run(
                ["bash", str(SCRIPT), str(cf), str(df)],
                env={"DEFERRED": "yes" if deferred else "no", "PATH": "/usr/bin:/bin"},
                capture_output=True, text=True)

    def test_script_exists(self):
        self.assertTrue(SCRIPT.exists(), f"missing decision script: {SCRIPT}")

    def test_engine_changed_without_pin_bump_fails(self):
        r = self._run("src/stayawake/bots/security/matchers/heuristic.py\n", "")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("does not", (r.stdout + r.stderr))

    def test_engine_changed_with_pin_bump_passes(self):
        r = self._run("src/stayawake/bots/security/matchers/heuristic.py\n"
                      ".github/workflows/worm-guard.yml\n", PIN_BUMP_DIFF)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_engine_changed_deferred_passes(self):
        r = self._run("src/stayawake/bots/security/scanner.py\n", "", deferred=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_engine_change_passes(self):
        r = self._run("README.md\ndocs/security.md\nsrc/stayawake/cli.py\n", "")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_sibling_paths_do_not_trigger(self):
        # tests/ under a 'security' dir, and a sibling 'security_helpers' — neither is the engine.
        r = self._run("tests/bots/security/test_heuristic.py\n"
                      "src/stayawake/bots/security_helpers/util.py\n", "")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_pin_line_as_context_is_not_a_bump(self):
        # Engine changed; worm-guard.yml appears in the diff but the pin line is unchanged context.
        r = self._run("src/stayawake/bots/security/scanner.py\n", PIN_CONTEXT_DIFF)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_floating_ref_is_not_a_valid_bump(self):
        r = self._run("src/stayawake/bots/security/scanner.py\n", PIN_FLOATING_DIFF)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)


class TestPinsSynced(unittest.TestCase):
    """check_pins_synced.sh — every file that pins the scanner must hold the SAME reviewed SHA,
    so a bump can't land in one carrier and strand the other (as #1138 vs #1193 did)."""

    SHA_A = "b9ecff97618df680db4f3dc21855cdefc5986936"
    SHA_B = "5e28e6548d2275ee7cec3a0e141a9b53f6544bcb"

    def _pin(self, d: Path, name: str, ref: str) -> str:
        f = d / name
        f.write_text(f"          sentinel-ref: {ref}   # comment\n")
        return str(f)

    def _run(self, *files: str):
        return subprocess.run(
            ["bash", str(SCRIPT_SYNC), *files],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})

    def test_script_exists(self):
        self.assertTrue(SCRIPT_SYNC.exists(), f"missing sync script: {SCRIPT_SYNC}")

    def test_matching_pins_pass(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            r = self._run(self._pin(d, "a.yml", self.SHA_A), self._pin(d, "b.yml", self.SHA_A))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_mismatched_pins_fail(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            r = self._run(self._pin(d, "a.yml", self.SHA_A), self._pin(d, "b.yml", self.SHA_B))
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("mismatch", (r.stdout + r.stderr))

    def test_floating_ref_fails(self):
        # A carrier reset to `sentinel-ref: main` has no valid pin — the gate must not read it as
        # "in sync" just because it isn't a 40-hex SHA that differs.
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            r = self._run(self._pin(d, "a.yml", self.SHA_A), self._pin(d, "b.yml", "main"))
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_missing_pin_fails(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            b = d / "b.yml"
            b.write_text("no sentinel-ref here\n")
            r = self._run(self._pin(d, "a.yml", self.SHA_A), str(b))
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_single_carrier_is_trivially_synced(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            r = self._run(self._pin(d, "a.yml", self.SHA_A))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
