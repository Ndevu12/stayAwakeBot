#!/usr/bin/env python3
"""PR5 / #1146 — tail read-guard residuals: non-source bodies, magic-byte masquerade, symlink escape.

Closes the last read-guard blind spots of #1141: a payload under a non-source extension (oversized or
NUL-laden) is head-scanned by the CONFIRMED content tier only (FP-safe); an image/wasm/pdf whose bytes
are a script is flagged by the magic-byte masquerade check; a symlink resolving outside the repo root
is reported (SUSPICIOUS) without ever being followed. All against inert fixtures.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import CLEAN, INFECTED, SUSPICIOUS
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()


def _scan(files: dict, opts: ScanOptions | None = None):
    """files: {relpath: bytes}. Returns the ScanResult."""
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    return scan_target(LocalRepoTarget(d, "t", opts or ScanOptions()), SIGS, [])


def _ids(files, opts=None):
    return {f.signature_id for f in _scan(files, opts).findings}


class TestNonSourceBodyScan(unittest.TestCase):
    # (a) — the confirmed content tier now head-scans NON-source files (#6/#7), FP-safe.
    def test_payload_under_benign_ext_is_caught(self):
        self.assertIn("loader-fromcharcode-127",
                      _ids({"payload.bin": b"junk\nString.fromCharCode(127)\nmore"}))

    def test_nul_laden_non_source_is_caught(self):
        # A NUL in the head used to make read_text skip a non-source file wholesale (#7).
        self.assertIn("loader-seed-var", _ids({"x.dat": b"\x00\x00 var _$_1e42 = sfL(0);"}))

    def test_oversized_non_source_head_is_scanned(self):
        # >2 MB non-source: payload in the head, then padding — used to be skipped wholesale (#6).
        self.assertIn("loader-fromcharcode-127",
                      _ids({"big.log": b"String.fromCharCode(127)\n" + b"x" * 2_500_000}))

    def test_oversized_non_source_tail_is_scanned(self):
        # Head+tail (not head-only): a payload APPENDED past the cap is still seen.
        self.assertIn("loader-fromcharcode-127",
                      _ids({"big.log": b"x" * 2_500_000 + b"\nString.fromCharCode(127)\n"},
                           ScanOptions()))

    def test_genuine_binary_is_clean(self):
        # The confirmed content tier is FP-safe on real binary bytes (no loader tokens present).
        self.assertEqual(_ids({"a.bin": bytes(range(256)) * 20}), set())


class TestMagicByteMasquerade(unittest.TestCase):
    # (b) — an image/wasm/pdf ext whose bytes are text/script, no font-only restriction.
    def test_disguised_png_no_fingerprint_is_flagged(self):
        # A .png whose bytes are text/JS with NO known loader fingerprint → only the magic-byte
        # masquerade check catches it (the content tier needs a fingerprint). Confirmed → INFECTED,
        # same as a fake font (a binary that is actually a script has no benign explanation).
        r = _scan({"novel.png": b"// benign-looking\nfunction q(){ return globalThis }\n"})
        self.assertIn("disguised-binary-file", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)

    def test_disguised_wasm_and_pdf_flagged(self):
        self.assertIn("disguised-binary-file", _ids({"m.wasm": b"var x = 1; export default x;"}))
        self.assertIn("disguised-binary-file", _ids({"d.pdf": b"function evil(){} // not a pdf"}))

    def test_real_binaries_not_flagged(self):
        # Real magic bytes → the check short-circuits (0 FP).
        clean = {
            "a.png": b"\x89PNG\r\n\x1a\n" + os.urandom(400),
            "b.jpg": b"\xff\xd8\xff\xe0" + os.urandom(400),
            "c.gif": b"GIF89a" + os.urandom(400),
            "d.wasm": b"\x00asm\x01\x00\x00\x00" + os.urandom(400),
            "e.pdf": b"%PDF-1.7\n" + os.urandom(400),
            "f.woff2": b"wOF2" + os.urandom(400),
        }
        self.assertEqual(_ids(clean), set())

    def test_svg_text_not_flagged(self):
        # SVG is legitimately text/XML — deliberately NOT in BINARY_MAGIC (would FP on every file).
        self.assertEqual(_ids({"icon.svg": b"<svg><path d='M0 0'/></svg>"}), set())


class TestSymlinkEscape(unittest.TestCase):
    # (c) — report a symlink resolving OUTSIDE the repo root; never follow it.
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "a.js").write_text("const x = 1;\n")

    def _scan_dir(self):
        return scan_target(LocalRepoTarget(self.d, "t", ScanOptions()), SIGS, [])

    def test_escaping_dir_symlink_reported(self):
        outside = Path(tempfile.mkdtemp())
        (outside / "evil.js").write_text("String.fromCharCode(127)")
        (self.d / "escape").symlink_to(outside, target_is_directory=True)
        r = self._scan_dir()
        self.assertIn("symlink-escapes-repo", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, SUSPICIOUS)                 # heuristic — never INFECTED

    def test_escaping_file_symlink_is_residual_not_flagged(self):
        # FILE symlinks escaping the repo are a documented residual, NOT flagged: they are overwhelmingly
        # benign dev-env links (a venv's `bin/python -> /usr/.../python3.14`) → reporting them is noise.
        outside = Path(tempfile.mkdtemp())
        (outside / "secret").write_text("x")
        (self.d / "link").symlink_to(outside / "secret")
        self.assertNotIn("symlink-escapes-repo", {f.signature_id for f in self._scan_dir().findings})

    def test_in_repo_dir_symlink_is_clean(self):
        # A directory link that stays inside the repo (monorepo pattern) must NOT flag.
        (self.d / "pkg").mkdir()
        (self.d / "alias").symlink_to(self.d / "pkg", target_is_directory=True)
        self.assertNotIn("symlink-escapes-repo", {f.signature_id for f in self._scan_dir().findings})

    def test_symlink_loop_does_not_hang_or_crash(self):
        # A symlink cycle must be skipped safely (no ELOOP crash, no infinite walk / DoS).
        (self.d / "loop_a").symlink_to(self.d / "loop_b")
        (self.d / "loop_b").symlink_to(self.d / "loop_a")
        r = self._scan_dir()                                   # must simply complete
        self.assertIsNone(r.error)


@unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs need POSIX mkfifo")
class TestNonRegularFiles(unittest.TestCase):
    """#1226: a FIFO/socket/device with a scannable name must NOT hang the scanner's blocking open(),
    and is a BENIGN skip (a pipe has no static content) — never a recorded gap that fails the scan."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def _alarm(self, seconds=30):
        # Hard guard: if the read-path regresses to a blocking open() on the FIFO, fail fast instead of
        # hanging CI forever. (SIGALRM is POSIX — same availability as mkfifo, so this class is gated.)
        import signal
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError("scan hung on a FIFO")))
        signal.alarm(seconds)
        self.addCleanup(signal.alarm, 0)

    def test_fifo_is_skipped_not_read_and_not_a_gap(self):
        self._alarm()
        os.mkfifo(self.d / "evil.js")                          # a FIFO with a scannable extension
        (self.d / "real.js").write_text("const x = 1;\n")
        t = LocalRepoTarget(self.d, "t", ScanOptions())
        self.assertIsNone(t.read_text("evil.js"))             # returns at once, nothing to scan
        self.assertIsNone(t.read_bytes("evil.js"))
        self.assertEqual(list(t.read_source_windows("evil.js")), [])
        self.assertEqual(t.read_errors, [])                   # BENIGN skip — not a gap (no fail-closed)
        self.assertEqual(t.read_text("real.js"), "const x = 1;\n")   # real files still read

    def test_scan_over_a_repo_with_a_fifo_completes_cleanly(self):
        self._alarm()
        os.mkfifo(self.d / "pipe.js")
        (self.d / "ok.js").write_text("const y = 2;\n")
        r = scan_target(LocalRepoTarget(self.d, "t", ScanOptions()), SIGS, [])
        self.assertIsNone(r.error)                            # the FIFO didn't hang or fail the scan
        self.assertEqual(r.verdict, CLEAN)


if __name__ == "__main__":
    unittest.main()
