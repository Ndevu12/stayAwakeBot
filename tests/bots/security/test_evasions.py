#!/usr/bin/env python3
"""Scanner evasion regressions: NUL bytes, oversized files, and case/whitespace
mutations must not let a payload slip past the content matchers."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures

SIGS = load_signatures()


def _scan(d: Path, opts: ScanOptions | None = None):
    return {f.signature_id for f in
            scan_target(LocalRepoTarget(d, "t", opts or ScanOptions()), SIGS, []).findings}


class TestScannerEvasions(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def test_nul_byte_source_is_still_scanned(self):
        # C1: one NUL byte must not make a source file "binary" / invisible.
        (self.d / "nul.mjs").write_bytes(b"/*\x00*/ var _$_1e42 = sfL(0); export default {};")
        self.assertIn("loader-seed-var", _scan(self.d))

    def test_real_binary_without_source_ext_still_skipped(self):
        # A genuine binary asset (no source ext) stays skipped — no false positives.
        (self.d / "logo.png").write_bytes(b"\x89PNG\x00\x00 var _$_1e42 = sfL(")
        self.assertEqual(_scan(self.d), set())

    def test_oversized_source_file_tail_is_scanned(self):
        # C2: payload appended past the size cap is still found via head+tail scan.
        opts = ScanOptions(max_file_bytes=200)
        (self.d / "big.mjs").write_bytes(b"// pad\n" * 100 + b"\nString.fromCharCode(127);\n")
        self.assertIn("loader-fromcharcode-127", _scan(self.d, opts))

    def test_case_and_member_access_mutations_detected(self):
        # C3: case-flips, let/const, member access, hex arg must not evade.
        (self.d / "m.mjs").write_text(
            "LET _$_AB = SFL(0)\nString['fromCharCode'](0x7F)\n", encoding="utf-8")
        ids = _scan(self.d)
        self.assertIn("loader-seed-var", ids)
        self.assertIn("loader-decoder-fn", ids)
        self.assertIn("loader-fromcharcode-127", ids)


if __name__ == "__main__":
    unittest.main()
