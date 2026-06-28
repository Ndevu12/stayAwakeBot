#!/usr/bin/env python3
"""Git-recovery remediation for code-loader findings (the reliable replacement for the
surgical strip that corrupted valid files).

The promise: a code-loader payload is RECOVERED from the file's last clean committed
version, or DEFERRED to manual with a specific reason — never reconstructed/edited. So a
fix can never leave a syntactically broken file, and never wrongly touches intentional
test/research content.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security import remediation
from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.signatures import load_signatures

_SIGS_FLAT = [s for group in load_signatures().values() for s in group]
SIG = remediation.codeloader_content_sig(_SIGS_FLAT)

CLEAN = 'const config = { plugins: ["@tailwindcss/postcss"] };\nexport default config;\n'
# A loader payload: appended after `export default config;` (the worm's shape).
PAYLOAD = "var _$_1e42=sfL(0);String.fromCharCode(127);global['!']='x';" + "A1b2C3d4" * 30
# Payload appended as WHOLE NEW LINES, each an independent loader literal — the only
# provably-separable (auto-recoverable) shape.
PAYLOAD_LINES = "var _$_1e42=sfL(0);\nglobal['!']=require;\nString.fromCharCode(127);\n"


def _infected_newlines() -> str:
    return CLEAN + PAYLOAD_LINES


def _git(d: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(d), *args], check=True, capture_output=True)


def _repo() -> Path:
    d = Path(tempfile.mkdtemp())
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "t@t.local")
    _git(d, "config", "user.name", "t")
    _git(d, "config", "commit.gpgsign", "false")
    return d


def _commit(d: Path, rel: str, content: str, msg: str) -> None:
    p = d / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    _git(d, "add", rel)
    _git(d, "commit", "-q", "-m", msg)


def _finding(path: str, sig: str = "loader-seed-var") -> Finding:
    return Finding(sig, "code-loader", Severity.CRITICAL, path, "loader", remediation="recover")


def _infected_line() -> str:
    # clean file with the payload appended onto the export-default line (470-space pad).
    return CLEAN.rstrip("\n") + " " * 470 + PAYLOAD + "\n"


class TestRecovery(unittest.TestCase):
    def test_injected_newlines_recovers_exact_clean_version(self):
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        _commit(d, "postcss.config.mjs", _infected_newlines(), "feat: landing page")  # payload lands
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Recovery)
        ok = remediation.apply_recovery(d, disp, remediation.quarantine_path(d), SIG)
        self.assertTrue(ok)
        self.assertEqual((d / "postcss.config.mjs").read_text(), CLEAN)   # EXACT clean original
        self.assertNotIn("sfL", (d / "postcss.config.mjs").read_text())

    def test_uncommitted_injection_recovers_from_head(self):
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        (d / "postcss.config.mjs").write_text(_infected_newlines(), encoding="utf-8")  # not committed
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Recovery)
        self.assertTrue(remediation.apply_recovery(d, disp, remediation.quarantine_path(d), SIG))
        self.assertEqual((d / "postcss.config.mjs").read_text(), CLEAN)

    def test_same_line_payload_append_is_manual_not_recovered(self):
        # The payload shares the `export default config;` line → not provably separable from
        # any legit edit to that line → MANUAL with the exact recover command (never auto-edit).
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        (d / "postcss.config.mjs").write_text(_infected_line(), encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)
        self.assertEqual(disp.reason, remediation.LEGIT_CHANGES)
        self.assertIn("git checkout", disp.action)
        self.assertIn("sfL", (d / "postcss.config.mjs").read_text())     # file untouched

    def test_legit_line_adjacent_to_payload_is_manual(self):
        # A legit new line lands in the SAME appended block as the payload → recovery would
        # drop it → defer to manual (data-loss prevention, must-fix from the adversarial pass).
        d = _repo()
        _commit(d, "app.mjs", CLEAN, "add config")
        (d / "app.mjs").write_text(CLEAN + "export function ready(){ return true; }\n"
                                   + PAYLOAD_LINES, encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("app.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)            # NOT a Recovery
        self.assertIn("ready", (d / "app.mjs").read_text())        # legit code still present

    def test_born_infected_is_manual_not_recovered(self):
        # First (only) commit already carries a packed payload → no clean version exists.
        d = _repo()
        _commit(d, "loader.mjs", "export default {};\n" + _infected_line(), "init (poisoned)")
        disp = remediation.classify_recovery(d, _finding("loader.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)
        self.assertEqual(disp.reason, remediation.BORN_INFECTED)

    def test_intrinsic_literal_is_manual_allowlist(self):
        # A test file whose committed content contains a loader LITERAL (not packed) — there
        # is no clean version, but it must NOT be quarantined/edited: flag as intrinsic.
        d = _repo()
        src = ('def test_detects_loader():\n'
               '    assert "var _$_1e42 = sfL(0)" in scan_output\n')
        _commit(d, "tests/test_loader.py", src, "add detection test")
        disp = remediation.classify_recovery(d, _finding("tests/test_loader.py"), SIG)
        self.assertIsInstance(disp, remediation.Manual)
        self.assertEqual(disp.reason, remediation.INTRINSIC_MATCH)

    def test_legit_edits_on_top_of_payload_is_manual(self):
        d = _repo()
        _commit(d, "app.mjs", CLEAN, "add config")
        # one commit adds BOTH a legit line AND the payload → recovery would lose the legit line.
        mixed = CLEAN.replace("export default config;",
                              "export const VERSION = '2.0';\nexport default config;") \
                     .rstrip("\n") + PAYLOAD + "\n"
        _commit(d, "app.mjs", mixed, "feat + (hidden) payload")
        disp = remediation.classify_recovery(d, _finding("app.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)
        self.assertEqual(disp.reason, remediation.LEGIT_CHANGES)

    def test_untracked_file_is_manual(self):
        d = _repo()
        _commit(d, "README.md", "# repo\n", "init")
        (d / "evil.mjs").write_text(_infected_line(), encoding="utf-8")   # never added
        disp = remediation.classify_recovery(d, _finding("evil.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)
        self.assertEqual(disp.reason, remediation.UNTRACKED)

    def test_not_a_git_repo_is_manual(self):
        d = Path(tempfile.mkdtemp())                                      # no `git init`
        (d / "x.mjs").write_text(_infected_line(), encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("x.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)
        self.assertEqual(disp.reason, remediation.NO_VCS)

    # ── safety properties ───────────────────────────────────────────────────────
    def test_recovery_diff_redacts_payload_never_prints_raw(self):
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        _commit(d, "postcss.config.mjs", _infected_newlines(), "feat")
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Recovery)
        self.assertIn("obfuscated payload", disp.diff)            # redacted marker present
        self.assertNotIn("sfL", disp.diff)                       # raw payload NEVER shown
        self.assertNotIn("fromCharCode", disp.diff)
        self.assertIn("export default config;", disp.diff)       # the clean context line IS shown

    def test_apply_recovery_refuses_to_write_a_dirty_version(self):
        # Defense in depth: if asked to "recover" to content that itself scans dirty, refuse.
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        (d / "postcss.config.mjs").write_text(_infected_line(), encoding="utf-8")
        bad = remediation.Recovery("postcss.config.mjs", "deadbeef", "x", "", _infected_line())
        self.assertFalse(remediation.apply_recovery(d, bad, remediation.quarantine_path(d), SIG))
        # the working file is left untouched (no half-write)
        self.assertIn("sfL", (d / "postcss.config.mjs").read_text())


if __name__ == "__main__":
    unittest.main()
