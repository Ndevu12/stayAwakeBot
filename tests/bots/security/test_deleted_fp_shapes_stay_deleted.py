#!/usr/bin/env python3
"""Two detection shapes were built elsewhere, measured against real data, and removed as
false-positive engines: a bare length threshold, and a base64 blob.

`saw` does not ship either as a decisive signal — but it ships something adjacent to both, and the
reasoning that keeps them safe lives in three files. These pin it, so a later widening cannot
reintroduce an engine that was already measured and rejected."""
from __future__ import annotations

import base64
import unittest

from stayawake.bots.security.models import CONFIRMED, HEURISTIC
from stayawake.bots.security.obfuscation.entry import analyze_file
from stayawake.bots.security.signatures import load_signatures


def _signature(kind: str) -> dict:
    for group in load_signatures().values():
        for sig in group:
            if sig.get("kind") == kind:
                return sig
    raise AssertionError(f"no signature of kind {kind!r}")


class TestALengthThresholdIsNeverDecisiveOnItsOwn(unittest.TestCase):
    def test_it_cannot_drive_an_infected_verdict(self):
        self.assertEqual(_signature("long-line").get("confidence"), HEURISTIC)

    def test_it_is_restricted_to_authored_extensions(self):
        globs = _signature("long-line").get("file_globs")
        self.assertTrue(globs, "an unrestricted length threshold is the engine that was removed")

    def test_it_still_declares_a_threshold_to_be_corroborated_against(self):
        self.assertGreaterEqual(int(_signature("long-line").get("threshold", 0)), 1)


class TestABase64BlobIsNotObfuscation(unittest.TestCase):
    """It is ordinary data — a token, a key array, an inlined asset — at any size."""

    def test_a_large_contiguous_blob_is_not_decisive(self):
        blob = base64.b64encode(b"x" * 3000).decode()
        self.assertFalse(analyze_file(blob, constructs_only=True).obfuscated)

    def test_it_is_not_reached_by_the_wider_tier_either(self):
        blob = base64.b64encode(b"x" * 3000).decode()
        self.assertFalse(analyze_file(blob).obfuscated)

    def test_a_blob_inside_ordinary_source_stays_clean(self):
        blob = base64.b64encode(b"y" * 2000).decode()
        source = f'const KEY = "{blob}";\nmodule.exports = KEY;\n'
        self.assertFalse(analyze_file(source, constructs_only=True).obfuscated)


class TestWhatReplacedThemStillFires(unittest.TestCase):
    """The false-negative side. Removing the two engines must not have removed the detection they
    were reaching for — a self-evident executable construct is still decisive."""

    def _loader(self) -> str:
        charcode = "from" + "CharCode"
        run = "ev" + "al"
        return f"{run}(String.{charcode}(118,97,114))"

    def test_an_executable_construct_is_still_caught(self):
        self.assertTrue(analyze_file(self._loader(), constructs_only=True).obfuscated)

    def test_it_is_caught_inside_an_otherwise_ordinary_file(self):
        source = f"function ok(a) {{ return a + 1; }}\n{self._loader()}\n"
        self.assertTrue(analyze_file(source, constructs_only=True).obfuscated)

    def test_a_confirmed_signature_still_exists_to_corroborate_with(self):
        confirmed = [s for group in load_signatures().values() for s in group
                     if s.get("confidence", CONFIRMED) == CONFIRMED]
        self.assertTrue(confirmed, "nothing decisive is left to corroborate a shape against")


if __name__ == "__main__":
    unittest.main()
