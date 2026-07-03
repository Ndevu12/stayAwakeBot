#!/usr/bin/env python3
"""Whitespace / invisible-character concealment (#1098).

Detects the technique — a payload pushed off-screen behind a long horizontal-whitespace run, or
hidden with zero-width / bidi-control characters (Trojan Source) — even when the concealed payload
matches no fingerprint and the line is under the 2000-char long-line threshold. Invisible chars are
built from \\u escapes so this test file carries no literal invisible characters.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import SUSPICIOUS, CLEAN
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()
WC = "whitespace-concealment"
RUN = " " * 300           # a long space run — well over the 120-char off-screen threshold


def _scan(files, allow=None, exclude=(".git",)):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    opts = ScanOptions(exclude_dirs=set(exclude))
    return scan_target(LocalRepoTarget(d, "t", opts), SIGS, allow or [])


class TestWhitespaceConcealment(unittest.TestCase):
    def test_space_buried_payload_in_mjs_is_suspicious(self):
        r = _scan({"postcss.config.mjs": "const c = 1;" + RUN + "runHiddenPayload()"})
        self.assertIn(WC, {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, SUSPICIOUS)                 # heuristic, never INFECTED alone

    def test_space_buried_value_in_json(self):
        r = _scan({"config.json": json.dumps({"note": "ok" + RUN + "hiddenCommandHere"})})
        self.assertIn(WC, {f.signature_id for f in r.findings})

    def test_padded_command_in_tasks_json(self):
        # The .vscode/tasks.json command field padded with spaces so it looks empty (attack-chain).
        r = _scan({".vscode/tasks.json": '{"command": "' + RUN + 'node payload.js"}'})
        self.assertIn(WC, {f.signature_id for f in r.findings})

    def test_sub_2000_char_line_fires(self):
        # Today's blind spot: total line well under the 2000-char long-line threshold still fires.
        line = "x" + RUN + "payloadHere"
        self.assertLess(len(line), 2000)
        self.assertIn(WC, {f.signature_id for f in _scan({"a.mjs": line}).findings})

    def test_zero_width_space_flagged(self):
        r = _scan({"x.js": "const a = 1;\u200bconst hidden = 2;\n"})
        self.assertIn(WC, {f.signature_id for f in r.findings})

    def test_bidi_override_flagged_trojan_source(self):
        # A right-to-left override (U+202E) reorders how source reads vs runs (CVE-2021-42574);
        # \u202c is the matching pop-directional-formatting.
        r = _scan({"x.ts": "let ok = 1; \u202eevil\u202c\n"})
        self.assertIn(WC, {f.signature_id for f in r.findings})

    # ── False positives bounded ─────────────────────────────────────────────────
    def test_short_alignment_is_clean(self):
        r = _scan({"a.js": "const x = 1;" + (" " * 40) + "// aligned note\n"})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)

    def test_ascii_art_lone_char_is_clean(self):
        # A long run followed by a single (aligned) char is not concealment — the trailing content
        # must be non-trivial (>= a few chars).
        self.assertNotIn(WC, {f.signature_id for f in _scan({"b.js": "// *" + (" " * 200) + "*\n"}).findings})

    def test_emoji_zero_width_joiner_is_clean(self):
        # The emoji ZWJ (U+200D) is deliberately NOT in the concealment set — it appears in legit
        # string data (family/profession emoji), so it must not false-positive.
        r = _scan({"emoji.ts": 'export const FAMILY = "\U0001f468\u200d\U0001f469\u200d\U0001f467";\n'})
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_generated_context_suppressed(self):
        # Minified/bundled paths legitimately carry long runs → suppressed by the context gate.
        r = _scan({"dist/app.min.js": "a=" + RUN + "b"})
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_allowlist_suppresses_by_signature(self):
        r = _scan({"postcss.config.mjs": "x" + RUN + "payloadHere"},
                  allow=[{"signature": WC, "path_glob": "*.mjs"}])
        self.assertNotIn(WC, {f.signature_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()
