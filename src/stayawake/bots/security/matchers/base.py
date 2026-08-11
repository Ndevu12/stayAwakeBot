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

# Font-format magic bytes; a "font" lacking these but carrying text is a payload.
FONT_MAGIC = {
    ".woff2": b"wOF2", ".woff": b"wOFF",
    ".ttf": b"\x00\x01\x00\x00", ".otf": b"OTTO",
}

# Other binary-format magic bytes — an image/wasm/pdf whose bytes are actually a script is a disguised
# payload, the same masquerade the font check catches. Deliberately excludes text-based formats (SVG is
# real XML/text and would flag on every file). A file with one of these extensions whose head lacks its
# magic and reads as text/JS is flagged (see heuristic `_magic_byte_masquerade`). Measured 0 FP on 534
# real image/font/wasm/pdf files (real ones start with their magic → the check short-circuits).
BINARY_MAGIC = {
    ".png": b"\x89PNG\r\n\x1a\n", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8", ".webp": b"RIFF", ".bmp": b"BM", ".ico": b"\x00\x00\x01\x00",
    ".wasm": b"\x00asm", ".pdf": b"%PDF-",
}

# A remote fetch piped straight into an interpreter (curl|wget → sh/bash/node/…). ONE source, shared
# by the workflow and structural-json matchers (a run step / a hook command) so the shape can't drift;
# the npm-lifecycle-remote-fetch signature carries the same shape in signatures.yml (data-driven) —
# keep the three consistent. The gap is `[^|]{0,2048}`, BOUNDED not `[^|]*`: an unbounded run scans to
# end-of-string at every curl/wget anchor when no pipe follows → O(n²) ReDoS on a crafted command
# (#1156). A real `curl URL | sh` one-liner is far under 2048 chars, so the bound is detection-identical.
REMOTE_FETCH_INTO_INTERPRETER = re.compile(
    r"\b(?:curl|wget)\b[^|]{0,2048}\|\s*(?:sh|bash|node|bun|bunx|deno)\b", re.IGNORECASE)


def evidence(text: str, start: int, end: int, width: int = 80) -> str:
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
    # True iff this matcher processes each file INDEPENDENTLY (iterates `target.iter_files()` with no
    # cross-file state), so it can safely run over a SUBSET of files and have its findings merged —
    # the basis for within-target file parallelism (#1325). Whole-target matchers (git history,
    # lockfile audits, the symlink walk) keep the safe default False and always run once over the
    # full target. Verified per-matcher before enabling; defaulting False means a new matcher is
    # never silently chunked (which could split cross-file state) until it's reviewed.
    partitionable: bool = False

    def scan(self, target, signatures: list[dict[str, Any]]):
        raise NotImplementedError
