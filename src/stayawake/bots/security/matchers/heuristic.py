#!/usr/bin/env python3
"""Heuristic matcher — oversized lines and text-in-fontfile detection.

The `oversized-config-line` rule is the formatting-keyed signal for an appended/packed
payload in a hand-authored config. Raw line length is NOT decisive on its own: real
configs legitimately carry one very long line (a tailwind `safelist`, an eslint
`globals` object, an inlined `data:` URI, a long proxy URL). So the long-line signal is
CORROBORATED with the context-aware confidence lever (G5): a long line is reported only
when (a) the file's content carries a worm loader fingerprint, OR (b) the file is
context-scoped obfuscated/packed per `analyze_file` (high-entropy, packed-shape,
density-dominant — after stripping inline `data:` asset URIs). Vendored/minified/
generated paths are suppressed there, so dense bundles never reach this rule.
"""
from __future__ import annotations

import re

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, globs_ok, FONT_MAGIC, build_content_sig
from stayawake.bots.security.obfuscation import (
    analyze_file, is_generated_context, _AUTHORED_OBFUSCATABLE_EXTS,
)
from stayawake.bots.security.matchers.obfuscation import _ext

# Whitespace concealment (T1027/T1564): a payload pushed off-screen behind a long run of
# horizontal whitespace so the line looks empty in an editor without word-wrap.
# 120 = content beyond a typical editor width (~80-120 cols) is off-screen; set below the
# report's `{200,}` grep so an attacker padding to just-under-200 is still caught. The trailing
# content must be non-trivial (a lone aligned `{` / `*` is not concealment).
_MIN_HIDDEN_WHITESPACE_RUN = 120
_MIN_CONCEALED_CONTENT = 4
# A run of >=120 space / tab / no-break-space chars, then non-whitespace content. Escapes only
# — a security tool must not carry literal invisible chars in its own source.
# The leading `(?<![ \t\u00A0])` anchors the run to a line-start / after-non-whitespace boundary, so
# on an all-whitespace line `re.search` doesn't retry the run at every offset (that O(n) of retries x
# the O(n) greedy match was an O(n^2) ReDoS \u2014 #1158). `{...,}+` is possessive: the maximal run never
# backtracks. Detection is identical (a real concealment run always follows a non-whitespace char or
# the line start; verified parity on every case) \u2014 a 2 MB all-whitespace line ~20 s -> 0.05 s.
_HIDDEN_WHITESPACE_RUN = re.compile(
    r"(?<![ \t\u00A0])(?P<run>[ \t\u00A0]{%d,}+)(?P<hidden>\S.*)$" % _MIN_HIDDEN_WHITESPACE_RUN)

# Zero-width / bidi-control characters that hide or reorder source text (the "Trojan Source"
# attack, CVE-2021-42574) and are essentially never legitimate in hand-authored code. Written as
# escapes on purpose. Deliberately EXCLUDES the emoji zero-width joiner (U+200D), ZWNJ (U+200C),
# variation selectors, and the BOM (U+FEFF, a legitimate file prefix) — those appear in real
# string data and would false-positive.
_CONCEALMENT_CHARS = re.compile(
    "[\u200b\u2060"                          # zero-width space, word joiner
    "\u202a\u202b\u202c\u202d\u202e"       # bidi embeddings/overrides (LRE RLE PDF LRO RLO)
    "\u2066\u2067\u2068\u2069]")            # bidi isolates (LRI RLI FSI PDI)


class HeuristicMatcher(Matcher):
    handles = "heuristic"

    def scan(self, target, signatures, all_signatures=None):
        findings: list[Finding] = []
        long_line = next((s for s in signatures if s.get("kind") == "long-line"), None)
        text_font = next((s for s in signatures if s.get("kind") == "text-in-fontfile"), None)
        concealment = next((s for s in signatures if s.get("kind") == "whitespace-concealment"), None)
        content_sig = build_content_sig(all_signatures or signatures)
        for rel in target.iter_files():
            if long_line and globs_ok(rel, long_line):
                f = self._oversized_line(target, rel, long_line, content_sig)
                if f:
                    findings.append(f)
            if text_font and globs_ok(rel, text_font):
                f = self._disguised_font(target, rel, text_font)
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
        # The raw formatting signal: at least one line longer than the threshold.
        long_hit = next(((i, len(ln)) for i, ln in enumerate(text.splitlines(), 1)
                         if len(ln) > th), None)
        if long_hit is None:
            return None
        # Context-aware corroboration. Generated/vendored paths are expected to carry long
        # dense lines → never corroborated here (suppressed exactly as the obfuscation matcher).
        if is_generated_context(rel):
            return None
        i, n = long_hit
        # (a) worm loader fingerprint anywhere in the file's content.
        hit = content_sig(text)
        if hit:
            return self._emit(sig, rel, f"line {i}: {n} chars; loader fingerprint: {hit}", i)
        # (b) context-scoped obfuscation verdict (only meaningful for authored exts; the
        #     globs already restrict to config/source extensions, but guard explicitly so
        #     a future glob widening can't leak a non-authored ext into analyze_file).
        if _ext(rel) in _AUTHORED_OBFUSCATABLE_EXTS:
            verdict = analyze_file(text, _ext(rel))
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
                       line=line, evidence=ev, vector=sig["category"])

    def _disguised_font(self, target, rel, sig):
        ext = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
        magic = FONT_MAGIC.get(ext)
        raw = target.read_bytes(rel, limit=512)
        if not raw or not magic or raw.startswith(magic):
            return None
        texty = sum(1 for b in raw[:256] if 9 <= b <= 126) > 200
        has_js = any(tok in raw for tok in (b"function", b"var ", b"=>", b"require", b"global"))
        if texty or has_js:
            return self._emit(sig, rel, f"{ext} without {magic!r} magic; content is text/JS")
        return None
