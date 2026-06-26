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

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, globs_ok, FONT_MAGIC, build_content_sig
from stayawake.bots.security.obfuscation import (
    analyze_file, is_generated_context, _AUTHORED_OBFUSCATABLE_EXTS,
)
from stayawake.bots.security.matchers.obfuscation import _ext


class HeuristicMatcher(Matcher):
    handles = "heuristic"

    def scan(self, target, signatures, all_signatures=None):
        findings: list[Finding] = []
        long_line = next((s for s in signatures if s.get("kind") == "long-line"), None)
        text_font = next((s for s in signatures if s.get("kind") == "text-in-fontfile"), None)
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
