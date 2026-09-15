#!/usr/bin/env python3
"""Matcher base class + shared parsing helpers.

One detection *technique* per sibling module; each subclass sets `handles` to the
signature `matcher` value it serves.
"""
from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Any

# Re-exported from the neutral leaf module so this file's existing importers (structural,
# npm_manifest, remediation) keep `from ...matchers.base import load_jsonc`, while the
# `dependencies/` package imports it directly and avoids a matchers↔dependencies cycle.
from stayawake.bots.security.jsonc import load_jsonc  # noqa: F401  (re-export)
from stayawake.bots.security.models import HEURISTIC

FONT_MAGIC = {
    ".woff2": b"wOF2", ".woff": b"wOFF",
    ".ttf": b"\x00\x01\x00\x00", ".otf": b"OTTO",
}

BINARY_MAGIC = {
    ".png": b"\x89PNG\r\n\x1a\n", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8", ".webp": b"RIFF", ".bmp": b"BM", ".ico": b"\x00\x00\x01\x00",
    ".wasm": b"\x00asm", ".pdf": b"%PDF-",
}

REMOTE_FETCH_INTO_INTERPRETER = re.compile(
    r"\b(?:curl|wget)\b[^|]{0,2048}\|\s*(?:sh|bash|node|bun|bunx|deno)\b", re.IGNORECASE)


def evidence(text: str, start: int, end: int, width: int = 80) -> str:
    """A window of the SCANNED FILE around a match — attacker bytes, verbatim.

    Every other matcher puts a sentence it wrote itself in `Finding.evidence`. This is the one that
    returns file content. The report fingerprints evidence by DEFAULT, so a caller needs no flag;
    `composed_evidence=True` is the opt-out and must never be set on a window built here."""
    s = max(0, start - 12)
    snippet = text[s:end + width].replace("\n", " ")
    return (snippet[:width] + "…") if len(snippet) > width else snippet


def globs_ok(relpath: str, sig: dict[str, Any]) -> bool:
    globs = sig.get("file_globs")
    if not globs:
        return True
    base = relpath.rsplit("/", 1)[-1]
    return any(fnmatch(relpath, g) or fnmatch(base, g) for g in globs)


def _content_check(signatures: list[dict[str, Any]], *, confirmed_only: bool,
                   corroborated: bool = False, categories=frozenset({"code-loader"})):
    """Compile the content fingerprints into `check(text) -> signature_id | None`. Takes the
    signatures, `confirmed_only` to drop heuristic tiers, `corroborated` to hold each signature to
    its declared corroborator, and `categories` to compile (None for every category). Matches the
    text and its newline-flattened form."""
    pats = [(s["id"], re.compile(s["pattern"], re.IGNORECASE), s.get("corroborate"))
            for s in signatures
            if s.get("pattern") and (categories is None or s.get("category") in categories)
            and not (confirmed_only and s.get("confidence") == HEURISTIC)]

    def check(text: str):
        flat = text.replace("\n", "").replace("\r", "")
        for sid, rx, needs in pats:
            if not (rx.search(text) or rx.search(flat)):
                continue
            if corroborated and needs:
                from .content import CORROBORATORS
                holds = CORROBORATORS.get(needs)
                if holds is not None and not holds(text) and not holds(flat):
                    continue
            return sid
        return None

    return check


def build_confirmed_loader_check(signatures: list[dict[str, Any]]):
    """CONFIRMED fingerprints only — for matchers whose finding drives a verdict. A heuristic
    shape is one benign code can share, so it must not be laundered into an accusation."""
    return _content_check(signatures, confirmed_only=True)


def build_corroborated_loader_check(signatures: list[dict[str, Any]]):
    """CONFIRMED fingerprints, each held to the corroboration its own entry declares — for callers
    judging a fragment where an uncorroborated hit is the documented false-positive class."""
    return _content_check(signatures, confirmed_only=True, corroborated=True)


def build_any_loader_check(signatures: list[dict[str, Any]]):
    """Every tier — for the remediation gate, which asks whether anything loader-shaped SURVIVED
    an excision. A heuristic match must still block a "fixed" claim. Tier grades how confidently
    we accuse, not how carefully we clean."""
    return _content_check(signatures, confirmed_only=False)


def build_any_payload_check(signatures: list[dict[str, Any]]):
    """`check(text) -> signature_id | None` over every content fingerprint, all tiers and
    categories. Takes the signatures; returns the check."""
    return _content_check(signatures, confirmed_only=False, categories=None)


class Matcher:
    handles: str = ""
    partitionable: bool = False

    def scan(self, target, signatures: list[dict[str, Any]]):
        raise NotImplementedError
