#!/usr/bin/env python3
"""`String.fromCharCode(127)` is how DEL is written, so the construct alone is vocabulary, not a tell.

Every RFC 7230 control-character table matched this loader fingerprint at CONFIRMED tier — the tier
that asserts malware — so an ordinary HTTP-parsing bundle scanned INFECTED and failed a CI gate.
Measured over 10,831 vendored files it hit two Microsoft-published header-token tables.

What separates a string SHUFFLER from a character TABLE is that the shuffler's output is executed, so
that is what the signature now requires. The construct is not deleted and the tier is not lowered.
"""
from __future__ import annotations

import re
import unittest

import yaml

from pathlib import Path
from stayawake.bots.security.matchers.content import CORROBORATORS

_SIGNATURES = Path(__file__).resolve().parents[3] / "src/stayawake/bots/security/data/signatures.yml"


def _signature(sig_id):
    for entry in yaml.safe_load(_SIGNATURES.read_text())["signatures"]:
        if entry.get("id") == sig_id:
            return entry
    raise AssertionError(f"{sig_id} is not in the signature file")


class TestTheConstructAloneIsNotAFinding(unittest.TestCase):
    def setUp(self):
        self.signature = _signature("loader-fromcharcode-127")
        self.pattern = re.compile(self.signature["pattern"], re.IGNORECASE)
        self.corroborate = CORROBORATORS[self.signature["corroborate"]]

    def _fires(self, source):
        from stayawake.bots.security.matchers.content import _corroborated
        match = self.pattern.search(source)
        return bool(match) and _corroborated(
            self.signature["corroborate"], source, match.start(), match.end())

    def test_it_still_asserts_malware_when_it_fires(self):
        # The tier is deliberately NOT lowered: the fix is corroboration, not a downgrade.
        self.assertEqual(self.signature["severity"], "critical")
        self.assertNotEqual(self.signature.get("confidence"), "heuristic")

    def test_an_rfc_7230_control_table_is_clean(self):
        self.assertFalse(self._fires(
            "const SP  = [String.fromCharCode(32), String.fromCharCode(9)];\n"
            "const DEL = [String.fromCharCode(127)];\n"
            "for (let f = 0; f < 31; f++) DEL.push(String.fromCharCode(f));\n"))

    def test_a_shuffler_whose_output_runs_still_fires(self):
        for name, source in {
            "eval": "var _0x=[String.fromCharCode(127)];eval(_0x.join(''));",
            "Function": "const s=String.fromCharCode(127);new Function(s)();",
            "constructor": "const p=String.fromCharCode(127);[]['constructor']['constructor'](p)();",
            "child_process": "const d=String.fromCharCode(127)+p;require('child_process').execSync(d);",
        }.items():
            with self.subTest(sink=name):
                self.assertTrue(self._fires(source))

    def test_the_mutation_tolerance_of_the_pattern_is_unchanged(self):
        for variant in ("String['fromCharCode'](0x7F)", "STRING.FROMCHARCODE(127)",
                        "String . fromCharCode ( 127 )"):
            with self.subTest(variant=variant):
                self.assertTrue(self.pattern.search(variant + ";eval(1);"))


class TestCorroborationIsProximityNotCoPresence(unittest.TestCase):
    """A minified bundle contains an exec sink somewhere by definition, so whole-file co-presence is
    not corroboration. Measured on the two vendored bundles that raised this: the nearest sink sits
    >20,000 characters from the character table, while every real shuffler executes within 100-500."""

    def setUp(self):
        self.signature = _signature("loader-fromcharcode-127")
        self.pattern = re.compile(self.signature["pattern"], re.IGNORECASE)

    def _fires(self, source):
        from stayawake.bots.security.matchers.content import _corroborated
        match = self.pattern.search(source)
        return bool(match) and _corroborated(
            self.signature["corroborate"], source, match.start(), match.end())

    def test_a_table_in_a_bundle_that_evals_far_away_stays_clean(self):
        far = ("const DEL=[String.fromCharCode(127)];" + "// pad\n" * 400 + "eval(cfg);")
        self.assertFalse(self._fires(far))

    def test_a_shuffler_separated_by_ordinary_code_still_fires(self):
        for filler in (40, 150):
            with self.subTest(lines=filler):
                near = ("const s=String.fromCharCode(127);" + "// filler\n" * filler + "eval(s);")
                self.assertTrue(self._fires(near))


class TestTheCorroboratorNameIsReal(unittest.TestCase):
    def test_every_declared_corroborator_exists(self):
        # A typo would otherwise read as "no corroboration required" for whichever signature has it.
        for entry in yaml.safe_load(_SIGNATURES.read_text())["signatures"]:
            if entry.get("corroborate"):
                with self.subTest(signature=entry["id"]):
                    self.assertIn(entry["corroborate"], CORROBORATORS)


if __name__ == "__main__":
    unittest.main()
