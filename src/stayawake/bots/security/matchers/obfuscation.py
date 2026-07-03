#!/usr/bin/env python3
"""Whole-file obfuscation matcher — line-AGNOSTIC payload detection (G4).

The formatting-keyed long-line rule (heuristic `oversized-config-line`) only fires
on a single line longer than its threshold. A payload that is SPLIT/WRAPPED onto
many shorter lines, or that lives in an extension that rule doesn't cover
(.jsx/.tsx/.vue/.svelte), slips straight past it. This matcher closes that gap: it
runs the worm content-loader fingerprints AND a context-scoped obfuscation detector
over the RAW concatenated file content — independent of any single line's length —
for hand-authored source/config files.

Context-aware confidence is the lever that keeps this FP-free: the detector is
applied ONLY to hand-authored extensions and ONLY outside vendored/minified/generated
locations (is_generated_context). In those generated paths obfuscation is expected
and suppressed; in hand-authored source it is anomalous and reported.
"""
from __future__ import annotations

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, build_content_sig
from stayawake.bots.security.obfuscation import (
    analyze_file,
    is_generated_context,
    _AUTHORED_OBFUSCATABLE_EXTS,
)


def _ext(rel: str) -> str:
    i = rel.rfind(".")
    return rel[i:].lower() if i != -1 else ""


class ObfuscationMatcher(Matcher):
    handles = "obfuscation"

    def scan(self, target, signatures, all_signatures=None):
        source_sig = next((s for s in signatures if s.get("kind") == "obfuscated-file"), None)
        build_artifact_sig = next(
            (s for s in signatures if s.get("kind") == "obfuscated-build-artifact"), None)
        # Opt-in (config `scan_build_outputs`): also inspect build/minified outputs, but only for
        # the self-evident obfuscation constructs (not the whole-file density heuristic).
        inspect_build_outputs = (bool(getattr(target.opts, "scan_build_outputs", False))
                                 and build_artifact_sig is not None)
        if not source_sig and not inspect_build_outputs:
            return []
        content_sig = build_content_sig(all_signatures or signatures)
        findings: list[Finding] = []
        for rel in target.iter_files():
            if _ext(rel) not in _AUTHORED_OBFUSCATABLE_EXTS:
                continue
            if is_generated_context(rel):       # vendored/minified/generated → obfuscation expected
                if inspect_build_outputs:
                    # Run only the self-evident construct checks here (a charcode array, exec sink,
                    # or base64/escape blob); the whole-file density heuristic stays off — density is
                    # expected in a bundle. Emitted as heuristic, never confirmed.
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
            # (a) line-agnostic loader fingerprint on the raw content.
            hit = content_sig(text)
            if hit:
                findings.append(self._emit(source_sig, rel, f"loader fingerprint on raw content: {hit}"))
                continue
            # (b) context-scoped whole-file obfuscation (split/wrapped packed payload).
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
