#!/usr/bin/env python3
"""Heuristic matcher — oversized lines and text-in-fontfile detection."""
from __future__ import annotations

import re
import sys

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import (
    Matcher, globs_ok, FONT_MAGIC, BINARY_MAGIC, REMOTE_FETCH_INTO_INTERPRETER, build_confirmed_loader_check)
from stayawake.bots.security.obfuscation import analyze_file, is_generated_context
from stayawake.bots.security.obfuscation.heuristics import _AUTHORED_OBFUSCATABLE_EXTS
from stayawake.bots.security.matchers.obfuscation import _ext

_MIN_HIDDEN_WHITESPACE_RUN = 120
_MIN_CONCEALED_CONTENT = 4
_HIDDEN_WHITESPACE_RUN = re.compile(
    r"(?<![ \t\u00A0])(?P<run>[ \t\u00A0]{%d,}+)(?P<hidden>\S.*)$" % _MIN_HIDDEN_WHITESPACE_RUN)

_JS_TOKENS = (b"function", b"var ", b"=>", b"require", b"global")
_SVG_CAP = 1_000_000
_SVG_START = re.compile(r"<\?xml\b|<!DOCTYPE[ \t\r\n]{1,20}svg\b|<svg\b", re.IGNORECASE)
_SVG_END = re.compile(r"</svg[ \t\r\n]{0,20}>[ \t\r\n]{0,200}$", re.IGNORECASE)
_SVG_RUNS_SOMETHING = re.compile(r"<script|javascript:", re.IGNORECASE)


def _an_svg_image(target, rel) -> bool:
    """Tell whether a file is, from its first byte to its last, an SVG document that runs nothing: it
    opens as SVG or XML (never with a comment), closes at its last `</svg>`, and holds no script, no
    JavaScript and no download handed to an interpreter. Takes the target and the path. Returns the
    answer; a file larger than the cap is not one."""
    raw = target.read_bytes(rel, limit=_SVG_CAP + 1)
    if not raw or len(raw) > _SVG_CAP or any(token in raw for token in _JS_TOKENS):
        return False
    text = raw.decode("utf-8", "replace").lstrip("\ufeff \t\r\n")
    return (bool(_SVG_START.match(text)) and bool(_SVG_END.search(text))
            and not _SVG_RUNS_SOMETHING.search(text) and not REMOTE_FETCH_INTO_INTERPRETER.search(text))


_CONCEALMENT_CHARS = re.compile(
    "[\u200b\u2060"                          # zero-width space, word joiner
    "\u202a\u202b\u202c\u202d\u202e"       # bidi embeddings/overrides (LRE RLE PDF LRO RLO)
    "\u2066\u2067\u2068\u2069]")            # bidi isolates (LRI RLI FSI PDI)


class HeuristicMatcher(Matcher):
    handles = "heuristic"
    partitionable = True

    def scan(self, target, signatures, all_signatures=None):
        findings: list[Finding] = []
        long_line = next((s for s in signatures if s.get("kind") == "long-line"), None)
        masquerade = [s for s in signatures if s.get("kind") == "magic-byte-masquerade"]
        svg_image = next((s for s in signatures if s.get("kind") == "svg-under-an-image-name"), None)
        concealment = next((s for s in signatures if s.get("kind") == "whitespace-concealment"), None)
        content_sig = build_confirmed_loader_check(all_signatures or signatures)
        for rel in target.iter_files():
            if long_line and globs_ok(rel, long_line):
                f = self._oversized_line(target, rel, long_line, content_sig)
                if f:
                    findings.append(f)
            for sig in masquerade:                # fonts + images/wasm/pdf, disjoint globs → ≤1 fires
                if globs_ok(rel, sig):
                    f = self._magic_byte_masquerade(target, rel, sig, svg_image)
                    if f:
                        findings.append(f)
            if concealment and globs_ok(rel, concealment):
                f = self._whitespace_concealment(target, rel, concealment)
                if f:
                    findings.append(f)
        return findings

    def _oversized_line(self, target, rel, sig, content_sig):
        """Emit only a CORROBORATED oversized-line finding (G5). Scan ALL long lines on
        the RAW content (no early break) so a head/tail-truncation splice can't hide a
        long line behind a short first one; but require the file to be loader-fingerprinted
        OR context-scoped obfuscated, so a legitimately long config line stays clean."""
        text = target.read_text(rel)
        if text is None:
            return None
        th = int(sig.get("threshold", 2000))
        long_hit = next(((i, len(ln)) for i, ln in enumerate(text.splitlines(), 1)
                         if len(ln) > th), None)
        if long_hit is None:
            return None
        # Context-aware corroboration. Generated/vendored paths are expected to carry long
        # dense lines → never corroborated here (suppressed exactly as the obfuscation matcher).
        if is_generated_context(rel):
            return None
        i, n = long_hit
        hit = content_sig(text)
        if hit:
            return self._emit(sig, rel, f"line {i}: {n} chars; loader fingerprint: {hit}", i)
        # (b) context-scoped obfuscation verdict (only meaningful for authored exts; the
        #     globs already restrict to config/source extensions, but guard explicitly so
        #     a future glob widening can't leak a non-authored ext into analyze_file).
        if _ext(rel) in _AUTHORED_OBFUSCATABLE_EXTS:
            try:
                verdict = analyze_file(text, _ext(rel))
            except Exception as exc:  # fail-SAFE: skip this one file, never abort the repo sweep
                print(f"saw: obfuscation analysis skipped for {rel}: {type(exc).__name__}: {exc}",
                      file=sys.stderr)
                verdict = None
            if verdict:
                return self._emit(sig, rel, f"line {i}: {n} chars; {verdict.reason}", i)
        return None

    def _whitespace_concealment(self, target, rel, sig):
        """Flag a line that hides content off-screen — a long run of horizontal whitespace
        followed by non-trivial content, or a zero-width / bidi-control character (Trojan
        Source). Context-gated so minified/generated paths (where long runs are expected) are
        suppressed. Heuristic → SUSPICIOUS: long runs can rarely be benign (wide alignment)."""
        if is_generated_context(rel):
            return None
        text = target.read_text(rel)
        if text is None:
            return None
        for i, line in enumerate(text.splitlines(), 1):
            run = _HIDDEN_WHITESPACE_RUN.search(line)
            if run and len(run.group("hidden").strip()) >= _MIN_CONCEALED_CONTENT:
                return self._emit(
                    sig, rel, f"line {i}: {len(run.group('run'))}-char whitespace run hides content", i)
            invisible = _CONCEALMENT_CHARS.search(line)
            if invisible and line.strip():
                return self._emit(
                    sig, rel, f"line {i}: zero-width/bidi char U+{ord(invisible.group()):04X}", i)
        return None

    @staticmethod
    def _emit(sig, rel, ev, line=None):
        return Finding(signature_id=sig["id"], category=sig["category"],
                       severity=Severity.parse(sig["severity"]), path=rel,
                       description=sig["description"], remediation=sig.get("remediation", "manual"),
                       line=line, evidence=ev, vector=sig["category"], composed_evidence=True)

    def _magic_byte_masquerade(self, target, rel, sig, svg_image=None):
        """A file whose EXTENSION claims a binary format (font/image/wasm/pdf) but whose head lacks
        that format's magic bytes AND reads as text/JS → a payload disguised under a benign extension.
        """

        ext = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
        offset, magic = FONT_MAGIC.get(ext) or BINARY_MAGIC.get(ext) or (0, b"")
        raw = target.read_bytes(rel, limit=512)
        if not raw or not magic or raw[offset:offset + len(magic)] == magic:
            return None
        texty = sum(1 for b in raw[:256] if 9 <= b <= 126) > 200
        has_js = any(tok in raw for tok in _JS_TOKENS)
        if not (texty or has_js):
            return None
        if svg_image is not None and globs_ok(rel, svg_image) and _an_svg_image(target, rel):
            return self._emit(svg_image, rel, f"{ext} holding an SVG image")
        return self._emit(sig, rel, f"{ext} without {magic!r} magic; content is text/JS")
        return None
