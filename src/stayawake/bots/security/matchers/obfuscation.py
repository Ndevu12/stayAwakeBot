#!/usr/bin/env python3
"""Whole-file obfuscation matcher — line-AGNOSTIC payload detection (G4)."""
from __future__ import annotations

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, build_confirmed_loader_check
from stayawake.bots.security.obfuscation import analyze_file, is_generated_context
from stayawake.bots.security.obfuscation.heuristics import _AUTHORED_OBFUSCATABLE_EXTS


def _ext(rel: str) -> str:
    i = rel.rfind(".")
    return rel[i:].lower() if i != -1 else ""


class ObfuscationMatcher(Matcher):
    handles = "obfuscation"
    partitionable = True

    def scan(self, target, signatures, all_signatures=None):
        source_sig = next((s for s in signatures if s.get("kind") == "obfuscated-file"), None)
        build_artifact_sig = next(
            (s for s in signatures if s.get("kind") == "obfuscated-build-artifact"), None)
        inspect_build_outputs = (bool(getattr(target.opts, "scan_build_outputs", False))
                                 and build_artifact_sig is not None)
        if not source_sig and not inspect_build_outputs:
            return []
        content_sig = build_confirmed_loader_check(all_signatures or signatures)
        findings: list[Finding] = []
        for rel in target.iter_files():
            if _ext(rel) not in _AUTHORED_OBFUSCATABLE_EXTS:
                continue
            if is_generated_context(rel):       # vendored/minified/generated → obfuscation expected
                if inspect_build_outputs:
                    text = target.read_text(rel)
                    verdict = analyze_file(text, _ext(rel), constructs_only=True) if text else None
                    if verdict:
                        findings.append(self._emit(build_artifact_sig, rel, verdict.reason))
                continue                        # default: build outputs are suppressed entirely
            if not source_sig:
                continue
            text = target.read_text(rel)
            if not text:
                continue
            hit = content_sig(text)
            if hit:
                findings.append(self._emit(source_sig, rel, f"loader fingerprint on raw content: {hit}"))
                continue
            verdict = analyze_file(text, _ext(rel))
            if verdict:
                findings.append(self._emit(source_sig, rel, verdict.reason))
        return findings

    @staticmethod
    def _emit(sig, rel, ev):
        return Finding(signature_id=sig["id"], category=sig["category"],
                       severity=Severity.parse(sig["severity"]), path=rel,
                       description=sig["description"], remediation=sig.get("remediation", "manual"),
                       evidence=ev, vector=sig["category"])
