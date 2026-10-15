#!/usr/bin/env python3
"""The marker a known loader sets on the global object reads infected however it is quoted or spaced."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import INFECTED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.support import samples


def _scan(text: str):
    root = Path(tempfile.mkdtemp(prefix="marker-"))
    try:
        (root / "index.js").write_text(text, encoding="utf-8")
        return scan_target(LocalRepoTarget(root, "x", ScanOptions()), load_signatures(), [])
    finally:
        shutil.rmtree(root, True)


class TestTheMarkerReadsInfected(unittest.TestCase):
    def test_every_quoting_and_spacing_reads_infected(self):
        for text in (f"{samples.GLOBAL}['_V']='8-12';\n", f'{samples.GLOBAL}["_V"]=\'8-12\';\n',
                     f"{samples.GLOBAL}[ '_V' ]='8-12';\n", f'{samples.GLOBAL}[ "_V" ] = "8-12";\n',
                     f"{samples.GLOBAL}[\t'_V'\t]\t=\t1;\n"):
            with self.subTest(text=text):
                result = _scan(text)
                self.assertEqual(result.verdict, INFECTED)
                self.assertIn("loader-global-v-marker", {f.signature_id for f in result.findings})

    def test_a_different_key_is_not_the_marker(self):
        result = _scan(f'{samples.GLOBAL}["_W"]=1;\n')
        self.assertNotIn("loader-global-v-marker", {f.signature_id for f in result.findings})


if __name__ == "__main__":
    unittest.main()
