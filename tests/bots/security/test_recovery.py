#!/usr/bin/env python3
"""Recovery remediation for code-loader findings — the safe replacement for the unbounded
surgical strip that corrupted valid files.

The promise: a code-loader payload is always resolved to a CLEAN COMMITTED version — either
RECOVERED directly (git restore, when the delta is a clean payload-only append), or SURGICALLY
EXCISED when excising a concealment-hidden seam (+ a now-dead require-shim) reproduces that clean
committed version BYTE-FOR-BYTE (so nothing injected can ride along in the kept code), or DEFERRED
to manual with a specific reason. A clean committed ancestor is required either way. Never an
unbounded textual transform, never fabricated bytes; every result is re-proven, symlink-guarded,
and quarantine-backed before it is written.
"""
from __future__ import annotations

import base64
import hashlib
import os
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


def _git_out(d: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(d), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


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


# The worm's require-shim: an ESM file has no CommonJS `require`, so a require-based payload
# prepends this bridge. `saw fix` removes it too — but only when it's dead (unused) after the
# payload is gone.
_SHIM = ("import { createRequire } from 'module';\n\n"
         "const require = createRequire(import.meta.url);\n\n")


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

    def test_same_line_concealment_seam_is_surgically_excised(self):
        # The payload is hidden behind a whitespace-concealment SEAM on the `export default config;`
        # line — a provable boundary the general same-line case lacks. It is now surgically EXCISED
        # (keep the clean prefix, drop the concealed packed payload), preserving every other byte,
        # rather than deferred to manual. The result is byte-exact to the clean version.
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        (d / "postcss.config.mjs").write_text(_infected_line(), encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Recovery)
        self.assertTrue(disp.excised)
        self.assertTrue(remediation.apply_recovery(d, disp, remediation.quarantine_path(d), SIG))
        self.assertEqual((d / "postcss.config.mjs").read_text(), CLEAN)   # payload gone, rest intact
        self.assertNotIn("sfL", (d / "postcss.config.mjs").read_text())

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
        # First (only) commit is WHOLLY packed (no clean prefix, no concealment seam) → no clean
        # version to restore AND nothing for the seam-excision to safely keep → defer.
        d = _repo()
        _commit(d, "loader.mjs", PACKED_PAYLOAD + "\n", "init (poisoned)")
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
        # A wholly-packed untracked file: no committed clean version AND no seam to excise → defer.
        # (An untracked file whose payload IS seam-hidden is instead excised — see TestSeamExcision.)
        d = _repo()
        _commit(d, "README.md", "# repo\n", "init")
        (d / "evil.mjs").write_text(PACKED_PAYLOAD + "\n", encoding="utf-8")   # never added, wholly packed
        disp = remediation.classify_recovery(d, _finding("evil.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)
        self.assertEqual(disp.reason, remediation.UNTRACKED)

    def test_not_a_git_repo_is_manual(self):
        d = Path(tempfile.mkdtemp())                                      # no `git init`
        (d / "x.mjs").write_text(PACKED_PAYLOAD + "\n", encoding="utf-8")  # wholly packed, no seam
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

    def test_mixed_legit_and_payload_on_new_line_defers(self):
        # #1190: a NEW line that concatenates legit code with an appended packed loader is dense +
        # fingerprinted, so the old density-only insert check would DROP it whole — reverting the
        # legit statement. Per-statement accounting refuses it (the readable statement isn't
        # payload). Covered end-to-end for legit BEFORE and legit AFTER the blob.
        for label, line in (("before", "module.exports=runServer;" + PACKED_PAYLOAD),
                            ("after", PACKED_PAYLOAD + "doLegit();")):
            with self.subTest(shape=label):
                d = _repo()
                _commit(d, "app.mjs", CLEAN, "add config")
                _commit(d, "app.mjs", CLEAN + line + "\n", "add export (worm appended payload)")
                disp = remediation.classify_recovery(d, _finding("app.mjs"), SIG)
                self.assertIsInstance(disp, remediation.Manual)          # NOT a Recovery
                self.assertEqual(disp.reason, remediation.LEGIT_CHANGES)  # defers as legit-changes
                # apply must NOT drop the legit statement even if a Recovery were forced.
                self.assertFalse(remediation.apply_recovery(
                    d, remediation.Recovery("app.mjs", "x", "x", "", CLEAN),
                    remediation.quarantine_path(d), SIG))
                self.assertIn("runServer" if label == "before" else "doLegit",
                              (d / "app.mjs").read_text())               # legit code intact

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

    def test_line_is_pure_payload_accepts_pure_refuses_mixed(self):
        # #1190 per-statement gate: a pure packed loader line is payload; the SAME blob with a
        # legit statement concatenated in front is NOT (that statement is readable, not payload).
        self.assertTrue(remediation._line_is_pure_payload(PACKED_PAYLOAD, SIG))
        self.assertFalse(remediation._line_is_pure_payload("module.exports=runServer;" + PACKED_PAYLOAD, SIG))
        self.assertFalse(remediation._line_is_pure_payload(PACKED_PAYLOAD + "doLegit();", SIG))  # trailing legit
        # a legit inlined base64 ASSET (no loader fingerprint) is refused, never dropped.
        self.assertFalse(remediation._line_is_pure_payload('const IMG="' + _HIENT + '";', SIG))

    def test_stmt_is_payload_classifies_statements(self):
        self.assertTrue(remediation._stmt_is_payload("var _$_1e42=sfL(0)", SIG))   # fingerprinted loader
        self.assertTrue(remediation._stmt_is_payload(_HIENT, SIG))                 # pure encoded blob
        self.assertTrue(remediation._stmt_is_payload("   ", SIG))                  # concealment-only
        self.assertFalse(remediation._stmt_is_payload("module.exports=runServer", SIG))  # legit statement

    def test_is_packed_line_rejects_short_readable_lines(self):
        self.assertFalse(remediation._is_packed_line("export const DEL = String.fromCharCode(127);"))
        self.assertFalse(remediation._is_packed_line("global['!']=boot(); export const PORT = 3000;"))
        self.assertTrue(remediation._is_packed_line(PACKED_PAYLOAD))


class TestRecoveryHardening(unittest.TestCase):
    """#1185 shipped two provable hardenings to the recovery engine: the recovery SOURCE is
    selected from first-parent (mainline) history only, and apply re-proves the delta is
    payload-only + a subsequence of the working file before writing (verify-or-revert)."""

    def test_clean_source_only_via_second_parent_is_not_trusted(self):
        # Evil-merge topology: the file is introduced onto mainline THROUGH the merge, taking the
        # payload from the second (malicious) parent, whose branch also carries an attacker-staged
        # "clean" blob. Default git-log simplification follows the second parent (the merge is
        # TREESAME to it) and would surface that off-mainline clean blob as a recovery source.
        # The first-parent walk must refuse it: mainline never held a clean version of this file.
        d = _repo()
        _commit(d, "README.md", "# repo\n", "init (no m.mjs on mainline)")
        branch = _git_out(d, "rev-parse", "--abbrev-ref", "HEAD") or "master"
        _git(d, "checkout", "-q", "-b", "side")
        _commit(d, "m.mjs", CLEAN, "attacker-staged clean-looking blob (side only)")
        _commit(d, "m.mjs", CLEAN + PACKED_PAYLOAD + "\n", "side tip: payload")
        _git(d, "checkout", "-q", branch)
        _git(d, "merge", "--no-ff", "-m", "merge side (brings payload onto mainline)", "side")

        # The clean blob IS reachable via the default (simplified) walk, but NOT via first-parent.
        full = remediation.gitutil.file_commits(d, "m.mjs")
        fp = remediation.gitutil.file_commits(d, "m.mjs", first_parent=True)
        self.assertTrue(any(remediation.gitutil.file_at(d, s, "m.mjs") == CLEAN for s in full))
        self.assertFalse(any(remediation.gitutil.file_at(d, s, "m.mjs") == CLEAN for s in fp))

        disp = remediation.classify_recovery(d, _finding("m.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)                 # never recovers to the side blob
        self.assertIn("global", (d / "m.mjs").read_text())              # file untouched, still infected

    def test_first_parent_recovery_still_works_on_linear_history(self):
        # Sanity: the first-parent narrowing must not break the ordinary linear-history recovery.
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        _commit(d, "postcss.config.mjs", _infected_newlines(), "feat: landing page")
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Recovery)
        self.assertTrue(remediation.apply_recovery(d, disp, remediation.quarantine_path(d), SIG))
        self.assertEqual((d / "postcss.config.mjs").read_text(), CLEAN)

    def test_apply_reverts_when_clean_text_would_fabricate_or_drop_bytes(self):
        # Strengthened post-condition: a Recovery whose clean_text scans clean but is NOT 'the
        # working file minus payload' (fabricated / would drop legit code) is refused BEFORE any
        # write — proven at apply time independently of the planner.
        d = _repo()
        _commit(d, "a.mjs", CLEAN, "add config")
        (d / "a.mjs").write_text(_infected_newlines(), encoding="utf-8")
        fabricated = remediation.Recovery("a.mjs", "deadbeef", "x", "", "export const HACKED = 1;\n")
        self.assertFalse(remediation.apply_recovery(d, fabricated, remediation.quarantine_path(d), SIG))
        self.assertIn("global", (d / "a.mjs").read_text())              # untouched, payload intact
        self.assertNotIn("HACKED", (d / "a.mjs").read_text())           # fabricated text never written


class TestSeamExcision(unittest.TestCase):
    """The concealment-seam surgical excision: a confirmed loader hidden after a long whitespace
    run on a line of real code is cut out (clean prefix kept), preserving every other byte — no
    clean git ancestor required. A now-DEAD require-shim the worm prepended is removed too; a shim
    the config actually uses is kept. Re-proven at apply time and quarantined first."""

    def test_excises_payload_and_dead_shim_byte_exact(self):
        # The full worm shape on a config: prepended require-shim + same-line concealment payload.
        # Excise BOTH → byte-exact to the clean original.
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        (d / "postcss.config.mjs").write_text(_SHIM + _infected_line(), encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Recovery)
        self.assertTrue(disp.excised)
        self.assertTrue(remediation.apply_recovery(d, disp, remediation.quarantine_path(d), SIG))
        result = (d / "postcss.config.mjs").read_text()
        self.assertEqual(result, CLEAN)                       # shim + payload both gone, byte-exact
        self.assertNotIn("createRequire", result)

    def test_keeps_a_shim_the_config_actually_uses(self):
        # A config that legitimately uses `require` (so its shim is real, present in clean history):
        # the shim is NOT dead → kept. The excision reproduces the clean committed version (shim +
        # require + config, payload gone), so it corroborates and auto-cleans without breaking it.
        d = _repo()
        clean_with_shim = _SHIM + "const tw = require('@tailwindcss/postcss');\n" + CLEAN
        _commit(d, "postcss.config.mjs", clean_with_shim, "add config that uses require")
        infected = clean_with_shim.rstrip("\n") + " " * 470 + PAYLOAD + "\n"   # worm seam on last line
        (d / "postcss.config.mjs").write_text(infected, encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Recovery)
        self.assertTrue(disp.excised)
        self.assertTrue(remediation.apply_recovery(d, disp, remediation.quarantine_path(d), SIG))
        result = (d / "postcss.config.mjs").read_text()
        self.assertEqual(result, clean_with_shim)                  # byte-exact: shim + require kept
        self.assertNotIn("sfL", result)                            # payload gone

    def test_no_ancestor_seam_offers_a_suggested_strip(self):
        # #1209: with no git history to corroborate against, the seam excision can't AUTO-apply
        # (no trusted version to prove nothing ELSE was injected into the kept code) — but the strip
        # is structurally proven by `_seam_strip`'s five self-contained gates, so saw offers it as a
        # computed Suggested fix for the operator to review, instead of a bare hand-hunt checklist.
        # The file is NOT modified — only a git-corroborated Recovery is ever auto-written.
        d = Path(tempfile.mkdtemp())                               # no git init
        (d / "next.config.mjs").write_text(_infected_line(), encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("next.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Suggested)
        self.assertEqual(disp.reason, remediation.NO_VCS)
        self.assertEqual(disp.excised_text, CLEAN)                 # the computed strip is byte-exact clean
        self.assertNotIn("sfL", disp.diff)                         # payload redacted in the preview
        self.assertIn("sfL", (d / "next.config.mjs").read_text())  # file UNTOUCHED (not auto-applied)

    def test_no_ancestor_seam_with_visible_exec_sink_in_kept_stays_manual(self):
        # #1209 safety: even without an ancestor, if the KEPT code carries a DETECTABLE exec sink,
        # `_seam_strip` gate 4 refuses → no Suggested, defer to a full Manual investigation. A
        # computed strip is only ever offered when the kept code is free of detectable payload/exec
        # sinks — the same gate that protects the git-corroborated path protects this one.
        d = Path(tempfile.mkdtemp())                               # no git
        rce = "globalThis.x = require('vm').runInThisContext('a');\n" + _infected_line()
        (d / "next.config.mjs").write_text(rce, encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("next.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)            # NOT offered as a clean strip
        self.assertIn("runInThisContext", (d / "next.config.mjs").read_text())

    def test_hidden_rce_in_kept_code_defers_via_corroboration(self):
        # THE edge-case fix: an RCE the scanner CAN'T see (`require('vm').runInThisContext`) injected
        # into kept code, co-resident with a worm seam. Excising the seam would leave the RCE — but
        # the payload-stripped file no longer matches any clean commit (the RCE was injected, not in
        # history), so corroboration REFUSES to auto-clean → manual review. Closes the whole class of
        # undetectable-sink-in-kept-code holes without relying on a complete exec-sink detector.
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")      # clean ancestor has NO rce
        rce = "globalThis.x = require('vm').runInThisContext('a');\n" + _infected_line()
        (d / "postcss.config.mjs").write_text(rce, encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Manual)            # NOT auto-cleaned
        self.assertEqual(disp.reason, remediation.LEGIT_CHANGES)
        self.assertIn("runInThisContext", (d / "postcss.config.mjs").read_text())   # file untouched

    def test_legit_edit_since_infection_offers_a_suggested_strip(self):
        # #1209: a legit edit made after infection means the payload-stripped file no longer equals
        # any pre-infection clean commit, so the excision can't AUTO-apply (the edit isn't in trusted
        # history). But `_seam_strip` PRESERVES that edit (every non-seam byte kept) and is
        # structurally proven, so it is offered as a computed Suggested fix to review — not a bare
        # defer. The legit edit survives in the computed strip; the file itself is untouched.
        d = _repo()
        _commit(d, "postcss.config.mjs", CLEAN, "add config")
        edited = CLEAN.replace("export default config;",
                               "export const VERSION = '2';\nexport default config;")
        (d / "postcss.config.mjs").write_text(edited.rstrip("\n") + " " * 470 + PAYLOAD + "\n",
                                              encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("postcss.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Suggested)
        self.assertEqual(disp.reason, remediation.LEGIT_CHANGES)
        self.assertIn("VERSION", disp.excised_text)                        # legit edit preserved in strip
        self.assertNotIn("sfL", disp.excised_text)                         # payload gone from the strip
        self.assertIn("VERSION", (d / "postcss.config.mjs").read_text())   # file untouched (not applied)

    def test_apply_refuses_a_tampered_excision(self):
        # apply re-proves by RE-RUNNING the canonical strip on the file NOW; a clean_text that is
        # not what the strip produces (here it also drops the legit config block) is refused before
        # any write — the excision can't be tricked into deleting real code.
        d = Path(tempfile.mkdtemp())
        (d / "c.mjs").write_text(_infected_line(), encoding="utf-8")
        tampered = remediation.Recovery("c.mjs", "(excised)", "x", "",
                                        "export default config;\n", excised=True)  # dropped the config
        self.assertFalse(remediation.apply_recovery(d, tampered, remediation.quarantine_path(d), SIG))
        self.assertIn("sfL", (d / "c.mjs").read_text())            # untouched, payload intact

    # ── #1209 (Option B): apply_suggested WRITES the computed strip (into the review branch) ──
    def test_apply_suggested_applies_the_computed_strip(self):
        # A Suggested (no git ancestor) is applied by the SAME write machinery as an excised Recovery:
        # re-prove _seam_strip on the live bytes, quarantine the original, write the strip, verify.
        # Payload gone, every other byte kept — the ONLY difference from Recovery is provenance.
        d = Path(tempfile.mkdtemp())                               # no git → NO_VCS Suggested
        (d / "next.config.mjs").write_text(_infected_line(), encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("next.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Suggested)
        q = remediation.quarantine_path(d)
        self.assertTrue(remediation.apply_suggested(d, disp, q, SIG))
        self.assertEqual((d / "next.config.mjs").read_text(), CLEAN)   # clean prefix kept byte-exact
        self.assertNotIn("sfL", (d / "next.config.mjs").read_text())   # payload stripped
        self.assertIn("sfL", (q / "next.config.mjs").read_text())      # original quarantined

    def test_apply_suggested_refuses_when_live_bytes_diverge(self):
        # Re-proof against the file NOW: if it changed since classify so the canonical strip no longer
        # reproduces excised_text, refuse before any write (the strip can't be applied to stale bytes).
        d = Path(tempfile.mkdtemp())
        (d / "next.config.mjs").write_text(_infected_line(), encoding="utf-8")
        disp = remediation.classify_recovery(d, _finding("next.config.mjs"), SIG)
        self.assertIsInstance(disp, remediation.Suggested)
        (d / "next.config.mjs").write_text("export default other;\n", encoding="utf-8")  # changed, no seam
        self.assertFalse(remediation.apply_suggested(d, disp, remediation.quarantine_path(d), SIG))
        self.assertEqual((d / "next.config.mjs").read_text(), "export default other;\n")  # untouched

    def test_apply_suggested_refuses_a_symlinked_target(self):
        # Same #1218 guard as apply_recovery: never write through a symlink (would clobber outside the
        # worktree with no backup). The computed strip shares the write path, so it inherits the guard.
        d = Path(tempfile.mkdtemp())
        (d / "real.mjs").write_text(_infected_line(), encoding="utf-8")
        os.symlink(d / "real.mjs", d / "link.mjs")
        sug = remediation.Suggested("link.mjs", "sig", remediation.NO_VCS, "x", "d", CLEAN, 1)
        self.assertFalse(remediation.apply_suggested(d, sug, remediation.quarantine_path(d), SIG))
        self.assertIn("sfL", (d / "real.mjs").read_text())         # real target untouched through link

    # ── adversarial negatives: the excision must NOT fire on legit near-misses ──
    def test_no_seam_direct_append_not_excised(self):
        # Payload appended with NO concealment seam (directly adjacent) → no provable boundary → defer.
        self.assertIsNone(remediation._seam_strip(CLEAN.rstrip("\n") + PACKED_PAYLOAD + "\n", ".mjs", SIG))

    def test_short_suffix_after_spaces_not_excised(self):
        # A SHORT legit statement after a big whitespace run is not a packed payload → left alone.
        line = CLEAN.rstrip("\n") + " " * 470 + "export const DEL = String.fromCharCode(127);\n"
        self.assertIsNone(remediation._seam_strip(line, ".mjs", SIG))

    def test_still_packed_result_not_excised(self):
        # If cutting the seam leaves a STILL-packed prefix (a genuinely minified/packed file, where
        # the excised part could be legit dense content), refuse — confine to hand-authored source.
        packed_prefix = _HIENT * 3                                 # a long base64 blob, no loader
        self.assertIsNone(remediation._seam_strip(packed_prefix + " " * 470 + PACKED_PAYLOAD + "\n", ".mjs", SIG))

    def test_legit_exec_sink_line_is_not_excised(self):
        # Adversarial data-loss catch: a legit hand-aligned line that USES a dynamic-exec sink
        # (atob/eval/Function) but carries NO worm loader literal must NOT be excised — the suffix
        # gate requires a confirmed loader fingerprint, not a generic sink.
        icon = "const ICON =" + " " * 30 + "atob('" + _HIENT + "').split('').map(c => c.charCodeAt(0));"
        self.assertIsNone(remediation._concealment_seam(icon, SIG))         # the atob line is not a seam
        f = CLEAN.rstrip("\n") + " " * 470 + PAYLOAD + "\n" + icon + "\n"    # legit line co-resident w/ payload
        self.assertIsNone(remediation._seam_strip(f, ".mjs", SIG))          # → defer, don't drop the decoder

    def test_reflective_constructor_result_is_not_auto_cleaned(self):
        # Adversarial false-all-clear catch: a stealth reflective `['constructor'](` RCE in the KEPT
        # prefix (which the normal sink detector carves out as a benign clone) must BLOCK the
        # auto-clean — else the excision would present an RCE-bearing file as clean, past review.
        f = "boot=new mod['constructor']('return 1')();" + " " * 30 + PACKED_PAYLOAD + "\n"
        self.assertIsNone(remediation._seam_strip(f, ".mjs", SIG))

    def test_symlinked_target_is_refused(self):
        # apply_recovery must NEVER write through a symlink: `write_text` follows the link (could
        # clobber a file outside the worktree) and no backup is taken, so verify-or-revert is dead.
        d = Path(tempfile.mkdtemp())
        (d / "real.mjs").write_text(_infected_line(), encoding="utf-8")
        os.symlink(d / "real.mjs", d / "link.mjs")
        rec = remediation.Recovery("link.mjs", "(excised)", "x", "", CLEAN, excised=True)
        self.assertFalse(remediation.apply_recovery(d, rec, remediation.quarantine_path(d), SIG))
        self.assertIn("sfL", (d / "real.mjs").read_text())      # real target untouched through the link

    def test_symlinked_ancestor_or_escape_is_refused(self):
        # Defense-in-depth: a finding path with a symlinked ANCESTOR directory (the write would
        # escape the worktree) is refused too — the containment check resolves the whole path,
        # so write-confinement doesn't rely on how the caller sourced the path.
        d = Path(tempfile.mkdtemp())
        outside = Path(tempfile.mkdtemp())
        (outside / "real.mjs").write_text(_infected_line(), encoding="utf-8")
        os.symlink(outside, d / "linkdir")                      # d/linkdir -> outside the worktree
        rec = remediation.Recovery("linkdir/real.mjs", "(excised)", "x", "", CLEAN, excised=True)
        self.assertFalse(remediation.apply_recovery(d, rec, remediation.quarantine_path(d), SIG))
        self.assertIn("sfL", (outside / "real.mjs").read_text())   # out-of-tree file untouched

    # ── white-box guards for the new predicates ──
    def test_concealment_seam_predicate(self):
        seam = "export default config;" + " " * 470 + PACKED_PAYLOAD
        self.assertEqual(remediation._concealment_seam(seam, SIG), "export default config;")
        self.assertIsNone(remediation._concealment_seam("const x = 1;", SIG))            # no seam
        self.assertIsNone(remediation._concealment_seam(" " * 470 + PACKED_PAYLOAD, SIG))  # no clean prefix
        self.assertIsNone(remediation._concealment_seam("a;" + " " * 470 + "short();", SIG))  # suffix not packed

    def test_worm_shim_detect_and_dead(self):
        self.assertIsNotNone(remediation._worm_shim_block(_SHIM + "const config={};\n"))
        self.assertIsNone(remediation._worm_shim_block("const x=1;\n"))                  # no shim
        self.assertIsNone(remediation._worm_shim_block("x;\n" + _SHIM))                  # not at file start
        self.assertTrue(remediation._shim_is_dead("const config = {};\n"))              # no require ref
        self.assertFalse(remediation._shim_is_dead("const t = require('x');\n"))        # require used


if __name__ == "__main__":
    unittest.main()
