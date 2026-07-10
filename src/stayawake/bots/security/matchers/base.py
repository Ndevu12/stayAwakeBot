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


def build_content_sig(signatures: list[dict[str, Any]]):
    """Compile the worm CONTENT-loader fingerprints (the `content` matcher's code-loader
    regex signatures) into one callable `check(text) -> signature_id | None`.

    Matches against the text AND its newline-flattened form, so a payload wrapped across
    lines still hits. Used wherever a matcher corroborates a structural signal (a long
    line, a merge-introduced hunk) against "is this actually a known loader" without
    re-running a full file scan. Patterns come from the live signature DB so the two never
    drift. Shared by the evil-merge, heuristic and obfuscation matchers (one source)."""
    pats = [(s["id"], re.compile(s["pattern"], re.IGNORECASE))
            for s in signatures if s.get("pattern") and s.get("category") == "code-loader"]

    def check(text: str):
        flat = text.replace("\n", "").replace("\r", "")
        for sid, rx in pats:
            if rx.search(text) or rx.search(flat):
                return sid
        return None

    return check


class Matcher:
    handles: str = ""

    def scan(self, target, signatures: list[dict[str, Any]]):
        raise NotImplementedError
