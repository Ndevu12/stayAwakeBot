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


def _loader_check(signatures: list[dict[str, Any]], *, confirmed_only: bool):
    """Compile the CONTENT-loader fingerprints into `check(text) -> signature_id | None`.

    Matches against the text AND its newline-flattened form, so a payload wrapped across lines
    still hits. Patterns come from the live signature DB so no consumer can drift from it."""
    pats = [(s["id"], re.compile(s["pattern"], re.IGNORECASE))
            for s in signatures
            if s.get("pattern") and s.get("category") == "code-loader"
            and not (confirmed_only and s.get("confidence") == HEURISTIC)]

    def check(text: str):
        flat = text.replace("\n", "").replace("\r", "")
        for sid, rx in pats:
            if rx.search(text) or rx.search(flat):
                return sid
        return None

    return check


def build_confirmed_loader_check(signatures: list[dict[str, Any]]):
    """CONFIRMED fingerprints only — for matchers whose finding drives a verdict. A heuristic
    shape is one benign code can share, so it must not be laundered into an accusation."""
    return _loader_check(signatures, confirmed_only=True)


def build_any_loader_check(signatures: list[dict[str, Any]]):
    """Every tier — for the remediation gate, which asks whether anything loader-shaped SURVIVED
    an excision. A heuristic match must still block a "fixed" claim. Tier grades how confidently
    we accuse, not how carefully we clean."""
    return _loader_check(signatures, confirmed_only=False)


class Matcher:
    handles: str = ""
    partitionable: bool = False

    def scan(self, target, signatures: list[dict[str, Any]]):
        raise NotImplementedError
