#!/usr/bin/env python3
"""Git-recovery remediation for code-loader findings (the reliable replacement for the
surgical strip that corrupted valid files).

The promise: a code-loader payload is RECOVERED from the file's last clean committed
version, or DEFERRED to manual with a specific reason — never reconstructed/edited. So a
fix can never leave a syntactically broken file, and never wrongly touches intentional
test/research content.
"""
from __future__ import annotations

import base64
import hashlib
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
# A deterministic high-entropy blob (base64 of sha256 digests) — stands in for a real packed
# payload's randomness without Math.random/Date in the test.
_HIENT = "".join(base64.b64encode(hashlib.sha256(str(i).encode()).digest()).decode() for i in range(8))
# A loader payload: appended after `export default config;` (the worm's shape).
PAYLOAD = "var _$_1e42=sfL(0);String.fromCharCode(127);global['!']='x';" + _HIENT
# The only auto-recoverable shape: the payload appended as ONE dense, high-entropy line that
# both reads as a packed blob (`_is_packed_line`) AND carries a loader literal (`content_sig`).
# A short loader line (e.g. a legit `String.fromCharCode(127)`) deliberately does NOT qualify.
PACKED_PAYLOAD = "var _$_1e42=sfL(0);global['!']=require;String.fromCharCode(127);" + _HIENT


def _infected_newlines() -> str:
    return CLEAN + PACKED_PAYLOAD + "\n"


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
        # A legit new line lands in the SAME appended block as a (recoverable-shaped) payload →
        # recovery would drop it → defer to manual (data-loss prevention from the adversarial pass).
        d = _repo()
        _commit(d, "app.mjs", CLEAN, "add config")
        (d / "app.mjs").write_text(CLEAN + "export function ready(){ return true; }\n"
                                   + PACKED_PAYLOAD + "\n", encoding="utf-8")
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

    # ── regressions for the second adversarial pass (data-loss + missed-infection) ────
    def test_short_loader_literal_line_is_not_dropped(self):
        # Holes A/B: a SHORT line that merely contains a loader fingerprint — a real
        # `String.fromCharCode(127)` (DEL handling), a `function sfL(...)` — must NEVER be
        # auto-dropped. It isn't a packed blob, so recovery defers to manual and leaves it intact.
        d = _repo()
        _commit(d, "term.mjs", CLEAN, "add config")
        legit = CLEAN + "export const DEL = String.fromCharCode(127); // erase char\n"
        (d / "term.mjs").write_text(legit, encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("term.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)                       # NOT a Recovery
        self.assertIn("String.fromCharCode(127)", (d / "term.mjs").read_text())  # legit line intact

    def test_payload_spliced_onto_legit_code_line_is_manual(self):
        # Hole C: content_sig is a SUBSTRING match, so a line that splices a loader token in
        # front of real code matches — but it is short/readable, not a packed blob, so it is
        # never dropped whole (which would take `export const PORT` with it).
        d = _repo()
        _commit(d, "srv.mjs", CLEAN, "add config")
        spliced = CLEAN + "global['!']=boot(); export const PORT = 3000;\n"
        (d / "srv.mjs").write_text(spliced, encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("srv.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)
        self.assertIn("export const PORT", (d / "srv.mjs").read_text())       # legit code intact

    def test_obfuscated_intermediate_version_is_not_treated_as_clean(self):
        # Hole D: history is clean → an eval(atob(...)) stage (a live payload with NO loader
        # literal yet) → the loader literal. The clean-rev walk must SKIP the eval/atob stage
        # (the broadened yardstick catches the exec sink) and recover to the truly-clean root.
        d = _repo()
        _commit(d, "loader.mjs", CLEAN, "v0 clean")
        _commit(d, "loader.mjs", CLEAN + "eval(atob('" + _HIENT + "'));\n", "v1 obfuscated")
        _commit(d, "loader.mjs", CLEAN + PACKED_PAYLOAD + "\n", "v2 loader")
        disp = remediation.classify_recovery(d, _finding("loader.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Recovery)
        self.assertEqual(disp.clean_text, CLEAN)        # the v0 root, NOT the v1 eval/atob stage
        self.assertNotIn("atob", disp.clean_text)

    def test_non_utf8_blob_in_history_does_not_crash(self):
        # Hole 1: a non-UTF-8 blob in history must not raise UnicodeDecodeError mid-walk (which
        # aborted remediation for the repo and the rest of the sweep). It degrades gracefully.
        d = _repo()
        (d / "data.mjs").write_bytes(b"const x = '\xff\xfe\x80\x81';\n")   # invalid UTF-8
        _git(d, "add", "data.mjs")
        _git(d, "commit", "-q", "-m", "binary-ish blob")
        (d / "data.mjs").write_text(CLEAN + PACKED_PAYLOAD + "\n", encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("data.mjs"), SIG)   # must not raise
        self.assertIsInstance(disp, (remediation.Recovery, remediation.Manual))

    # ── white-box guards for the two key predicates ──────────────────────────────────
    def test_carries_payload_flags_exec_sink_without_literal(self):
        self.assertTrue(remediation._carries_payload("eval(atob('QUFB'))", SIG))   # sink, no literal
        self.assertTrue(remediation._carries_payload("var _$_=sfL(0)", SIG))       # loader literal
        self.assertFalse(remediation._carries_payload("export const x = 1;", SIG)) # clean code

    def test_is_packed_line_rejects_short_readable_lines(self):
        self.assertFalse(remediation._is_packed_line("export const DEL = String.fromCharCode(127);"))
        self.assertFalse(remediation._is_packed_line("global['!']=boot(); export const PORT = 3000;"))
        self.assertTrue(remediation._is_packed_line(PACKED_PAYLOAD))


if __name__ == "__main__":
    unittest.main()
