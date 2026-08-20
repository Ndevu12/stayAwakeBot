#!/usr/bin/env python3
"""Destructive-intent matcher — surface the self-destruct / evidence-removal capability.

Runs the model-driven `taint.detect_destructive` flow detector over authored code / shell / manifest
files and emits the corroborated finding, choosing between the two DISTINCT signatures by variant:
`secure-home-wipe` (overwrite-then-delete → unrecoverable) vs `destructive-home-wipe` (plain delete →
recoverable). Confirmed-tier by the home-root ∧ recursive ∧ delete corroboration (near-zero benign use);
the detector itself carries the FP-safety, so this matcher is a thin surface + variant router.
"""
from __future__ import annotations

from stayawake.utils import env
from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.targets.base import CODE_EXTS
from stayawake.bots.security.taint.destructive import detect_destructive, SECURE

_RUNNER_NOTE = (" [ephemeral CI runner: local-wipe impact limited to the disposable job — "
                "prioritise credential rotation + lateral-movement checks]")


def _ext(rel: str) -> str:
    dot = rel.rfind(".")
    return rel[dot:].lower() if dot != -1 else ""


class DestructiveMatcher(Matcher):
    handles = "destructive"
    partitionable = True

    def scan(self, target, signatures, all_signatures=None):
        by_kind = {s.get("kind"): s for s in signatures}
        plain_sig = by_kind.get("destructive-home-wipe")
        secure_sig = by_kind.get("secure-home-wipe")
        if not (plain_sig or secure_sig):
            return []
        note = _RUNNER_NOTE if env.is_ephemeral_runner() else ""
        findings: list[Finding] = []
        for rel in target.iter_files():
            if _ext(rel) not in CODE_EXTS:       # code only — never prose/config (no snippet FP)
                continue
            text = target.read_text(rel)
            if not text:
                continue
            verdict = detect_destructive(text)
            if verdict is None:
                continue
            sig = (secure_sig or plain_sig) if verdict.variant == SECURE else (plain_sig or secure_sig)
            findings.append(Finding(
                signature_id=sig["id"], category=sig["category"],
                severity=Severity.parse(sig["severity"]), path=rel,
                description=sig["description"], remediation=sig.get("remediation", "manual"),
                evidence=verdict.reason + note, vector="destructive-wipe"))
        return findings
