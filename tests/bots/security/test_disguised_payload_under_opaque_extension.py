#!/usr/bin/env python3
"""Obfuscated script hidden under an extension saw does not recognise — a `.orc` posing as a font —
is flagged, while a real Csound `.orc`, minified CSS and a dense SVG are not."""
from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()

# An obfuscator-style payload: one long, dense, high-entropy, unbroken line.
_NOISE = "".join(base64.b64encode(hashlib.sha256(str(i).encode()).digest()).decode().rstrip("=")
                 for i in range(80))
_PACKED = "(function(_0xa,_0xb){var _0xc='" + _NOISE + "';return _0xc;}(0x1,0x2));"


def _ids(files: dict) -> set:
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    return {f.signature_id for f in scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, []).findings}


class TestDisguisedPayloadUnderOpaqueExtension(unittest.TestCase):
    def test_packed_script_under_an_opaque_extension_is_flagged(self):
        self.assertIn("obfuscated-source-file",
                      _ids({"src/fonts/fa-brand-400.orc": _PACKED.encode()}))

    def test_a_real_multiline_csound_orc_is_not_flagged(self):
        csound = "\n".join("instr %d\n  aSig oscili 0.5, 440\n  out aSig\nendin" % i
                           for i in range(1, 20))
        self.assertNotIn("obfuscated-source-file", _ids({"audio/synth.orc": csound.encode()}))

    def test_minified_css_and_dense_svg_do_not_false_positive(self):
        css = "".join(".c%d{color:red;margin:%dpx;padding:%dpx}" % (i, i, i) for i in range(2000))
        svg = '<svg><path d="M' + " ".join("%d L%d" % (i, i * 2) for i in range(4000)) + '"/></svg>'
        ids = _ids({"styles/app.min.css": css.encode(), "icons/sprite.svg": svg.encode()})
        self.assertNotIn("obfuscated-source-file", ids)


if __name__ == "__main__":
    unittest.main()
