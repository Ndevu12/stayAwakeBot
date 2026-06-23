#!/usr/bin/env python3
"""Heuristic matcher — oversized lines and text-in-fontfile detection."""
from __future__ import annotations

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, globs_ok, FONT_MAGIC


class HeuristicMatcher(Matcher):
    handles = "heuristic"

    def scan(self, target, signatures):
        findings: list[Finding] = []
        long_line = next((s for s in signatures if s.get("kind") == "long-line"), None)
        text_font = next((s for s in signatures if s.get("kind") == "text-in-fontfile"), None)
        for rel in target.iter_files():
            if long_line and globs_ok(rel, long_line):
                text = target.read_text(rel)
                if text is not None:
                    th = int(long_line.get("threshold", 2000))
                    for i, ln in enumerate(text.splitlines(), 1):
                        if len(ln) > th:
                            findings.append(self._emit(long_line, rel, f"line {i}: {len(ln)} chars", i))
                            break
            if text_font and globs_ok(rel, text_font):
                f = self._disguised_font(target, rel, text_font)
                if f:
                    findings.append(f)
        return findings

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
