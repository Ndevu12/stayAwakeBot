#!/usr/bin/env python3
"""Scanner evasion regressions: NUL bytes, oversized files, and case/whitespace
mutations must not let a payload slip past the content matchers."""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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

    def test_oversized_source_file_middle_is_scanned(self):
        # C2b (#1145, blind spot #5): a payload buried in the INTERIOR — neither head nor tail —
        # of an oversized source file must still be caught. On the head+tail-only reader this
        # payload sits between the 100 B head and 100 B tail and is invisible; the windowed
        # content reader streams the whole body so it is found.
        opts = ScanOptions(max_file_bytes=200)
        body = b"// pad\n" * 60 + b"\nString.fromCharCode(127);\n" + b"// pad\n" * 60
        (self.d / "mid.mjs").write_bytes(body)
        self.assertIn("loader-fromcharcode-127", _scan(self.d, opts))

    def test_oversized_source_middle_line_number_is_accurate(self):
        # The window base-line accounting must report the payload's real (large) line number, not a
        # window-local one — a payload after thousands of interior lines reports that absolute line.
        opts = ScanOptions(max_file_bytes=200)
        pre = b"// pad\n" * 500                      # 500 lines before the payload
        (self.d / "line.mjs").write_bytes(pre + b"String.fromCharCode(127);\n" + b"// pad\n" * 50)
        t = LocalRepoTarget(self.d, "t", opts)
        f = next(f for f in scan_target(t, SIGS, []).findings
                 if f.signature_id == "loader-fromcharcode-127")
        self.assertEqual(f.line, 501)               # 500 pad lines + the payload on line 501

    def test_source_match_straddling_a_window_boundary_is_caught(self):
        # A payload positioned to cross a window boundary must still be found whole — the window
        # overlap exists exactly so a boundary can't split a match. Here window=200, step=100, so the
        # payload at byte ~190 spans the 200-byte boundary; the second window ([100,300)) holds it whole.
        opts = ScanOptions(max_file_bytes=200)
        payload = b"String.fromCharCode(127);"
        body = b"x" * (190 - 0) + payload + b"y" * 400
        (self.d / "straddle.mjs").write_bytes(body)
        self.assertIn("loader-fromcharcode-127", _scan(self.d, opts))

    def test_oversized_over_ceiling_falls_back_to_head_tail(self):
        # A file larger than the interior-scan ceiling falls back to head+tail (bounded work, no
        # unbounded windowing) — an appended/tail payload is still caught; the deep middle is the
        # documented residual. Patch the ceiling small so we needn't write 64 MB.
        from stayawake.bots.security.targets import base as _base
        opts = ScanOptions(max_file_bytes=200)
        big = b"// pad\n" * 500 + b"\nString.fromCharCode(127);\n"   # payload in the TAIL
        (self.d / "huge.mjs").write_bytes(big)
        with mock.patch.object(_base, "_MAX_INTERIOR_SCAN_BYTES", 500):  # < file size → fallback path
            self.assertIn("loader-fromcharcode-127", _scan(self.d, opts))

    def test_large_spam_source_scans_without_catastrophic_backtracking(self):
        # Guardrail: the content tier must stay ~linear on a hostile multi-MB source file. If a future
        # content signature (re)introduces scan-to-EOF quadratic backtracking, windowing would amplify
        # it into a multi-minute hang — this asserts the whole scan of a 4 MB spam file stays fast.
        (self.d / "spam.js").write_bytes(b"curl _$_ String.fromCharCode " * 130_000)  # ~4 MB, hits prefilters
        t0 = time.time()
        _scan(self.d)                               # default 2 MB cap → real windowing over the interior
        self.assertLess(time.time() - t0, 20.0, "content scan of a 4 MB spam file is not ~linear")

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
