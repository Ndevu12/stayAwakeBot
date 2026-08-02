#!/usr/bin/env python3
"""The built-in RS256 signer (`lib/jwtsign`) — proven byte-for-byte equal to `openssl` (the reference)
and, when present, PyJWT; RSA blinding never changes the deterministic output; bad keys fail loud."""
from __future__ import annotations

import base64
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.lib import jwtsign

_HAVE_OPENSSL = shutil.which("openssl") is not None


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@unittest.skipUnless(_HAVE_OPENSSL, "needs openssl to generate keys / provide the reference signature")
class TestRs256AgainstOpenssl(unittest.TestCase):
    """RS256 is deterministic, so a correct signer's output must equal openssl's byte-for-byte."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.keys: dict[str, Path] = {}
        for bits in (2048, 4096):
            k1 = cls.tmp / f"pkcs1-{bits}.pem"
            subprocess.run(["openssl", "genrsa", "-out", str(k1), str(bits)],
                           check=True, capture_output=True)
            k8 = cls.tmp / f"pkcs8-{bits}.pem"
            subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(k1), "-out", str(k8)],
                           check=True, capture_output=True)
            cls.keys[f"pkcs1-{bits}"] = k1
            cls.keys[f"pkcs8-{bits}"] = k8

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_byte_equal_to_openssl_across_key_forms_and_sizes(self):
        payload = {"iat": 1, "exp": 541, "iss": "42"}
        for name, path in self.keys.items():
            jwt = jwtsign.encode_rs256(payload, path.read_text())
            signing_input, sig = jwt.rsplit(".", 1)
            ref = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(path)],
                                 input=signing_input.encode(), capture_output=True, check=True)
            self.assertEqual(sig, _b64url(ref.stdout), name)
            self.assertEqual(len(jwt.split(".")), 3, name)

    def test_blinding_is_deterministic(self):
        # blinding uses a random factor, but the RS256 output is identical every time.
        pem = self.keys["pkcs1-2048"].read_text()
        payload = {"iss": "x", "iat": 1, "exp": 2}
        self.assertEqual(jwtsign.encode_rs256(payload, pem), jwtsign.encode_rs256(payload, pem))


class TestErrorsFailLoud(unittest.TestCase):
    def test_encrypted_key_rejected(self):
        with self.assertRaises(jwtsign.JwtSignError):
            jwtsign.encode_rs256({}, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----")

    def test_non_pem_rejected(self):
        with self.assertRaises(jwtsign.JwtSignError):
            jwtsign.encode_rs256({}, "not a pem at all")

    def test_empty_rejected(self):
        with self.assertRaises(jwtsign.JwtSignError):
            jwtsign.encode_rs256({}, "")


try:
    import jwt as _pyjwt  # noqa: F401
    _HAVE_PYJWT = True
except Exception:  # noqa: BLE001
    _HAVE_PYJWT = False


@unittest.skipUnless(_HAVE_OPENSSL and _HAVE_PYJWT, "needs openssl + PyJWT")
class TestAgainstPyJWT(unittest.TestCase):
    def test_equal_to_pyjwt(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        k = tmp / "k.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(k), "2048"], check=True, capture_output=True)
        import jwt as pyjwt
        pem, payload = k.read_text(), {"iat": 1, "exp": 541, "iss": "9"}
        self.assertEqual(pyjwt.encode(payload, pem, algorithm="RS256"),
                         jwtsign.encode_rs256(payload, pem))


if __name__ == "__main__":
    unittest.main()
