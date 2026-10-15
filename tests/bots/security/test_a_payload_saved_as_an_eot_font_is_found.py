#!/usr/bin/env python3
"""A payload saved under an Embedded OpenType font's name reads as a disguised payload, and a real Embedded
OpenType font reads clean."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import CLEAN, INFECTED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.support.samples import FONT_PAYLOAD, INFECTED_PROJECT, joined

_DISGUISED = "fake-font-text-woff"
_HIDDEN = "whitespace-concealment"
_EOT = joined("public/fonts/fa-solid-900.", "eot")


def _scan(files: dict[str, bytes]):
    root = Path(tempfile.mkdtemp(prefix="eot-"))
    for rel, content in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(content)
    return scan_target(LocalRepoTarget(root, str(root), ScanOptions()), load_signatures(), [])


def _payload() -> bytes:
    return INFECTED_PROJECT[FONT_PAYLOAD[2:]]().encode("utf-8")


def _real_eot() -> bytes:
    name = "Icons".encode("utf-16-le")
    body = bytes(range(256)) * 4
    header = bytearray(82)
    struct.pack_into("<IIII", header, 0, 82 + 4 + len(name) + len(body), len(body), 0x00020001, 0)
    header[34:36] = b"LP"
    return bytes(header) + struct.pack("<HH", 0, len(name)) + name + body


class TestAPayloadSavedAsAnEotFontIsFound(unittest.TestCase):
    def test_a_payload_saved_as_an_eot_font_reads_infected(self):
        result = _scan({_EOT: _payload()})
        self.assertIn(_DISGUISED, {f.signature_id for f in result.findings})
        self.assertEqual(result.verdict, INFECTED)

    def test_a_real_eot_font_reads_clean(self):
        result = _scan({_EOT: _real_eot()})
        self.assertEqual([f.signature_id for f in result.findings], [])
        self.assertEqual(result.verdict, CLEAN)

    def test_the_mark_of_a_real_eot_font_counts_only_where_the_format_keeps_it(self):
        result = _scan({_EOT: b"LP" + _payload()})
        self.assertIn(_DISGUISED, {f.signature_id for f in result.findings})

    def test_code_hidden_behind_spaces_in_an_eot_font_is_flagged(self):
        result = _scan({_EOT: ("const c = 1;" + " " * 300 + "runHiddenPayload()").encode("utf-8")})
        self.assertIn(_HIDDEN, {f.signature_id for f in result.findings})

    def test_the_other_font_kinds_read_as_before(self):
        woff2 = joined("public/fonts/a.", "woff2")
        self.assertIn(_DISGUISED, {f.signature_id for f in _scan({woff2: _payload()}).findings})
        self.assertEqual(_scan({woff2: b"wOF2" + bytes(range(256)) * 2}).findings, [])


if __name__ == "__main__":
    unittest.main()
