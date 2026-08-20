#!/usr/bin/env python3
"""Dependency-free RS256 JWT signer for GitHub App auth (stdlib only)."""
from __future__ import annotations

import base64
import hashlib
import json
import os


class JwtSignError(Exception):
    """The private key can't be parsed, or isn't a supported unencrypted RSA key."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ── minimal DER (ASN.1) reader — only what an RSA private key needs ────────────────────────────────
def _read_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at offset `i` → (tag, value_bytes, next_offset)."""
    try:
        tag = data[i]
        length = data[i + 1]
        i += 2
        if length & 0x80:                              # long-form length
            nbytes = length & 0x7F
            length = int.from_bytes(data[i:i + nbytes], "big")
            i += nbytes
        value = data[i:i + length]
    except IndexError as e:
        raise JwtSignError("truncated DER while parsing the private key") from e
    if len(value) != length:
        raise JwtSignError("truncated DER value while parsing the private key")
    return tag, value, i + length


_RSA_OID = bytes.fromhex("2a864886f70d010101")


def _rsa_components(pem: str) -> tuple[int, int, int]:
    """Parse a PEM RSA private key → (n, e, d). Handles PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8
    (`BEGIN PRIVATE KEY`); rejects encrypted / non-RSA keys."""
    text = (pem or "").strip()
    if "ENCRYPTED" in text:
        raise JwtSignError("encrypted private keys are unsupported — provide an unencrypted PEM")
    body = "".join(ln for ln in text.splitlines() if ln and not ln.startswith("-----"))
    if not body:
        raise JwtSignError("no PEM body found in the private key")
    try:
        der = base64.b64decode(body)
    except Exception as e:  # noqa: BLE001
        raise JwtSignError(f"private key is not valid base64 PEM: {e}") from e

    pkcs1 = der
    if "BEGIN RSA PRIVATE KEY" not in text:            # PKCS#8 wrapper → unwrap to the PKCS#1 body
        _, seq, _ = _read_tlv(der, 0)
        _, _ver, j = _read_tlv(seq, 0)
        _, alg, j = _read_tlv(seq, j)
        _, alg_oid, _ = _read_tlv(alg, 0)
        if alg_oid != _RSA_OID:
            raise JwtSignError("private key is not an RSA key (unsupported algorithm)")
        _, pkcs1, _ = _read_tlv(seq, j)
    _, seq, _ = _read_tlv(pkcs1, 0)
    _, _v, j = _read_tlv(seq, 0)
    _, n_b, j = _read_tlv(seq, j)
    _, e_b, j = _read_tlv(seq, j)
    _, d_b, j = _read_tlv(seq, j)
    return int.from_bytes(n_b, "big"), int.from_bytes(e_b, "big"), int.from_bytes(d_b, "big")


_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1_v15(message: bytes, key_len: int) -> int:
    """EMSA-PKCS1-v1.5 encode `message`'s SHA-256 into an integer of the modulus byte-length."""
    t = _SHA256_DIGESTINFO + hashlib.sha256(message).digest()
    if key_len < len(t) + 11:
        raise JwtSignError("RSA key too small for RS256")
    em = b"\x00\x01" + b"\xff" * (key_len - len(t) - 3) + b"\x00" + t
    return int.from_bytes(em, "big")


def _sign(message: bytes, n: int, e: int, d: int) -> bytes:
    """RSASSA-PKCS1-v1.5 signature with RSA blinding (timing-side-channel hardening)."""
    key_len = (n.bit_length() + 7) // 8
    m = _emsa_pkcs1_v15(message, key_len)
    for _ in range(16):                                # retry until r is coprime to n (near-certain)
        r = int.from_bytes(os.urandom(key_len), "big") % n
        if r <= 1:
            continue
        try:
            r_inv = pow(r, -1, n)
        except ValueError:
            continue
        blinded = (m * pow(r, e, n)) % n
        s = (pow(blinded, d, n) * r_inv) % n
        return s.to_bytes(key_len, "big")
    raise JwtSignError("could not obtain a blinding factor coprime to the modulus")


def encode_rs256(payload: dict, private_key_pem: str) -> str:
    """Encode `payload` as an RS256-signed JWT with the RSA `private_key_pem`. Header is fixed
    `{"alg":"RS256","typ":"JWT"}`. Raises `JwtSignError` on an unusable key."""
    n, e, d = _rsa_components(private_key_pem)
    signing_input = (
        _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
        + "." + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    return signing_input + "." + _b64url(_sign(signing_input.encode("ascii"), n, e, d))
