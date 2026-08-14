#!/usr/bin/env python3
"""A code signature must answer WHO signed, not merely whether the bytes are intact.

`codesign --verify` alone is an integrity check, and an ad-hoc signature satisfies it for free —
`codesign -s -`, no certificate, no account. On Apple Silicon `ld(1)` ad-hoc signs by default, so a
bare verify is near-inert there and the `signed is False` branch that `Attribution.attributed` leans
on becomes unreachable. `--strict` was worse than useless in the other direction: it rejects
legitimately signed Developer ID software over "resource fork, Finder information, or similar
detritus", so real vendors read as unsigned.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.hygiene.autorun import provenance


@unittest.skipUnless(sys.platform == "darwin", "codesign is macOS-only")
class TestSignatureAnswersIdentityNotIntegrity(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=Path.home()))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _copy(self, name):
        target = self.dir / name
        shutil.copy("/bin/echo", target)
        subprocess.run(["codesign", "--remove-signature", str(target)], capture_output=True)
        return target

    def test_an_ad_hoc_signature_is_not_a_signature(self):
        # One command, no certificate. Under a bare `--verify` this returned True.
        binary = self._copy("adhoc")
        signed = subprocess.run(["codesign", "-s", "-", str(binary)], capture_output=True)
        if signed.returncode != 0:
            self.skipTest("codesign could not ad-hoc sign here")
        self.assertIs(provenance._codesigned(str(binary)), False)

    def test_an_unsigned_binary_is_still_unsigned(self):
        self.assertIs(provenance._codesigned(str(self._copy("unsigned"))), False)

    def test_apple_signed_system_binaries_still_pass(self):
        self.assertIs(provenance._codesigned("/bin/echo"), True)

    def test_developer_id_software_is_not_called_unsigned(self):
        # `--strict` failed these on packaging detritus while their authority chain was valid, so a
        # shipping notarized app read as unsigned and lost its attribution.
        apps = sorted(Path("/Applications").glob("*.app/Contents/MacOS/*"))
        third_party = [a for a in apps if a.is_file()
                       and provenance._run(["codesign", "--verify", str(a)]) is not None]
        checked = 0
        for app in third_party:
            verify = provenance._run(["codesign", "--verify", str(app)])
            if verify is None or verify.returncode != 0:
                continue                       # genuinely broken or unsigned — not this test's subject
            checked += 1
            self.assertIs(provenance._codesigned(str(app)), True, f"called unsigned: {app}")
            if checked >= 3:
                break
        if not checked:
            self.skipTest("no verifiable third-party application on this host")

    def test_a_missing_binary_asserts_nothing(self):
        self.assertIsNone(provenance._codesigned(str(self.dir / "absent")))


if __name__ == "__main__":
    unittest.main()
