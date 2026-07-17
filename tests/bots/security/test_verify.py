#!/usr/bin/env python3
"""Tests for content-verifying a suspect directory (`verify_dir`) — the #1221 corroboration
`saw audit` delegates to.

Payloads are ASSEMBLED AT RUNTIME (this source carries no contiguous IoC literal) and written to
throwaway temp dirs (never the repo tree), so the self-scan gate stays green with no
`config/security.yml` allowlist entry."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.verify import DEFAULT_MAX_FILES, verify_dir


def _confirmed_payload() -> str:
    """A JS snippet that triggers a CONFIRMED loader signature (loader-fromcharcode-127), assembled
    from split tokens so this file carries no contiguous IoC literal for the self-scan to flag."""
    cc = "from" + "CharCode"
    run = "ev" + "al"
    return f"const x = String.{cc}(127) + String.{cc}(127); {run}(x);"


def _tree() -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "package.json").write_text('{"name":"x","version":"1.0.0"}', encoding="utf-8")
    return d


class TestVerifyDir(unittest.TestCase):
    def test_confirmed_marker_inside_node_modules_is_found(self):
        # The whole point of #1221: excludes are OFF, so a payload inside node_modules/ (which a
        # normal repo scan SKIPS) is seen and reported.
        d = _tree()
        nm = d / "node_modules" / "evil"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text(_confirmed_payload(), encoding="utf-8")
        v = verify_dir(d)
        self.assertTrue(v.has_markers, v)
        self.assertIn("loader-fromcharcode-127", v.markers)
        self.assertFalse(v.scanned_clean)
        self.assertFalse(v.too_large)

    def test_clean_tree_is_scanned_clean(self):
        d = _tree()
        lib = d / "node_modules" / "lib"
        lib.mkdir(parents=True)
        (lib / "index.js").write_text("module.exports = function (a, b) { return a + b; };\n",
                                      encoding="utf-8")
        v = verify_dir(d)
        self.assertTrue(v.scanned_clean, v)
        self.assertEqual(v.markers, [])
        self.assertIsNone(v.error)
        self.assertFalse(v.has_markers)
        self.assertGreaterEqual(v.files, 2)

    def test_minified_library_is_not_a_false_positive(self):
        # A tree of minified/obfuscated-LOOKING legit code trips heuristic density, NOT a confirmed
        # signature — confirmed-only grading keeps it calm (no crying wolf on a real node_modules).
        d = _tree()
        big = d / "node_modules" / "big"
        big.mkdir(parents=True)
        (big / "min.js").write_text("var a=function(b,c){return b+c};" * 500, encoding="utf-8")
        v = verify_dir(d)
        self.assertTrue(v.scanned_clean, v)
        self.assertEqual(v.markers, [])

    def test_too_large_bails_without_claiming_clean(self):
        d = _tree()
        nm = d / "node_modules"
        nm.mkdir()
        for i in range(6):
            (nm / f"f{i}.js").write_text("x", encoding="utf-8")
        v = verify_dir(d, max_files=3)
        self.assertTrue(v.too_large, v)
        self.assertFalse(v.scanned_clean)      # never claimed clean when we didn't fully look
        self.assertFalse(v.has_markers)

    def test_missing_path_is_error_not_clean(self):
        v = verify_dir(Path(tempfile.mkdtemp()) / "does-not-exist")
        self.assertIsNotNone(v.error)
        self.assertFalse(v.scanned_clean)
        self.assertFalse(v.has_markers)

    def test_a_file_is_error_not_scanned(self):
        f = Path(tempfile.mkdtemp()) / "a.js"
        f.write_text("x", encoding="utf-8")
        v = verify_dir(f)
        self.assertIsNotNone(v.error)
        self.assertFalse(v.scanned_clean)

    # ── coverage honesty: never claim clean over a tree we didn't fully READ ───────────
    def test_escaping_dir_symlink_is_partial_not_clean(self):
        # An escaping DIRECTORY symlink is never descended → its contents go unscanned. Must NOT read
        # as clean (regression for the adversarial honesty-hunt, PATH C).
        outside = Path(tempfile.mkdtemp())
        (outside / "evil.js").write_text(_confirmed_payload(), encoding="utf-8")
        root = _tree()
        os.symlink(outside, root / "pkg")
        v = verify_dir(root)
        self.assertFalse(v.scanned_clean)
        self.assertTrue(v.partial)
        self.assertFalse(v.has_markers)             # payload sat behind the (unscanned) link

    def test_oversized_nonsource_file_is_partial_not_clean(self):
        # A non-source file over the 2MB cap is only head+tail-scanned; a payload in the middle is
        # unseen, so we must NOT claim clean (regression for the honesty-hunt, PATH B).
        root = _tree()
        (root / "blob.dat").write_text("A" * 1_500_000 + _confirmed_payload() + "B" * 1_500_000,
                                       encoding="utf-8")
        v = verify_dir(root)
        self.assertFalse(v.scanned_clean)
        self.assertTrue(v.partial)

    def test_large_source_file_under_cap_is_still_clean(self):
        # A SOURCE file over 2MB but under the 64MB interior cap is windowed in FULL → it must NOT be
        # flagged partial, or every large minified bundle would punt (over-conservative).
        root = _tree()
        (root / "big.js").write_text("var a = 1;\n" * 250_000, encoding="utf-8")   # ~2.7MB, benign
        v = verify_dir(root)
        self.assertTrue(v.scanned_clean, v)
        self.assertFalse(v.partial)

    def test_within_root_symlink_does_not_punt(self):
        # A dir symlink pointing WITHIN root (target walked via its real path) is fine — not partial
        # (avoids over-punting on pnpm-style symlinked node_modules).
        root = _tree()
        (root / "real").mkdir()
        (root / "real" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        os.symlink(root / "real", root / "link")
        v = verify_dir(root)
        self.assertTrue(v.scanned_clean, v)
        self.assertFalse(v.partial)

    _NEEDS_POSIX_NONROOT = (os.name == "posix" and not (hasattr(os, "geteuid") and os.geteuid() == 0))

    @unittest.skipUnless(_NEEDS_POSIX_NONROOT, "chmod-based unreadable tests need a non-root POSIX host")
    def test_symlink_to_unreadable_file_is_partial(self):
        # A FILE symlink whose target EXISTS but is unreadable is silently benign-skipped by the
        # scanner (no read gap recorded) — verify must still refuse clean (honesty-hunt round 2, PATH D).
        outside = Path(tempfile.mkdtemp())
        secret = outside / "secret.js"
        secret.write_text(_confirmed_payload(), encoding="utf-8")
        os.chmod(secret, 0)
        self.addCleanup(lambda: os.chmod(secret, 0o644))
        root = _tree()
        os.symlink(secret, root / "link.js")
        v = verify_dir(root)
        self.assertFalse(v.scanned_clean)
        self.assertTrue(v.partial)

    @unittest.skipUnless(_NEEDS_POSIX_NONROOT, "chmod-based unreadable tests need a non-root POSIX host")
    def test_unreadable_subdir_is_partial(self):
        # os.walk cannot list an unreadable directory — its files go unscanned silently, so verify
        # must not claim clean over it (the honesty-hunt PATH D twin).
        root = _tree()
        locked = root / "locked"
        locked.mkdir()
        (locked / "evil.js").write_text(_confirmed_payload(), encoding="utf-8")
        os.chmod(locked, 0)
        self.addCleanup(lambda: os.chmod(locked, 0o755))
        v = verify_dir(root)
        self.assertFalse(v.scanned_clean)
        self.assertTrue(v.partial)

    def test_dangling_symlink_is_still_clean(self):
        # A broken/dangling symlink has no content behind it → not a coverage gap.
        root = _tree()
        os.symlink(root / "does-not-exist", root / "dead.js")
        v = verify_dir(root)
        self.assertTrue(v.scanned_clean, v)
        self.assertFalse(v.partial)

    @unittest.skipUnless(os.name == "posix", "FIFO test needs POSIX (os.mkfifo)")
    def test_fifo_does_not_hang_and_is_not_clean(self):
        # A FIFO/named-pipe with a source extension would BLOCK the scanner's open() forever. verify
        # must classify it via stat() BEFORE opening and skip the scan, returning honestly (out-of-
        # class DoS surfaced by the round-3 refuter). The thread-timeout makes a regression FAIL, not
        # hang the suite.
        import threading
        root = _tree()
        os.mkfifo(root / "pipe.js")
        box: dict = {}
        th = threading.Thread(target=lambda: box.__setitem__("v", verify_dir(root)), daemon=True)
        th.start()
        th.join(timeout=15)
        self.assertFalse(th.is_alive(), "verify_dir HUNG on a FIFO")
        self.assertFalse(box["v"].scanned_clean)
        self.assertTrue(box["v"].partial)

    def test_universal_confirmed_content_signature_exists(self):
        # verify_dir's "fully read" guarantee holds only because the DB ships >=1 CONFIRMED `content`
        # signature with NO file_globs, so ContentMatcher reads EVERY file (content.py `if not sigs:
        # continue`). Pin that invariant: if a future DB restricted every content signature to
        # file_globs, unmatched files would go UNREAD while _survey reports complete — a silent
        # false-clean of the exact class the honesty refuters found (round-3 latent-coupling residual).
        content = load_signatures().get("content", [])
        universal_confirmed = [s for s in content
                               if s.get("confidence", "confirmed") == "confirmed"
                               and not s.get("file_globs")]
        self.assertTrue(universal_confirmed,
                        "no universal (no-file_globs) CONFIRMED content signature — verify_dir's "
                        "coverage model would silently break")

    def test_signatures_can_be_injected(self):
        # A caller verifying several dirs loads the DB once and passes it in.
        sigs = load_signatures()
        v = verify_dir(_tree(), signatures=sigs)
        self.assertTrue(v.scanned_clean)

    def test_default_cap_is_reasonable(self):
        self.assertGreaterEqual(DEFAULT_MAX_FILES, 1000)


if __name__ == "__main__":
    unittest.main()
