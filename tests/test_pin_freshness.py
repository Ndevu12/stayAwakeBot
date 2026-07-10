#!/usr/bin/env python3
"""Guard for the in-band scanner-pin freshness check (.github/scripts/check_pin_freshness.sh).

That script is what stops the worm-guard gate's pinned scanner (`sentinel-ref`) from silently
drifting behind the detection engine: a PR that changes `src/stayawake/bots/security/**` must also
bump the pin, or carry the `pin-bump-deferred` label. A bug here fails OPEN (drift sails through)
or fails CLOSED (blocks unrelated PRs), so the decision logic — and its fiddly boundaries — is
pinned by these cases. The script is GitHub-free (diff files + one env var in, exit code out)
precisely so it can be tested here instead of only in CI.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / ".github" / "scripts" / "check_pin_freshness.sh"

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


if __name__ == "__main__":
    unittest.main()
