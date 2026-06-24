#!/usr/bin/env python3
"""Regex-over-text-files matcher."""
from __future__ import annotations

import re

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, evidence, globs_ok


class ContentMatcher(Matcher):
    handles = "content"

    def scan(self, target, signatures):
        # IGNORECASE so trivial case-flips (let/LET, SFL vs sfL, 0X7F) don't evade.
        compiled = [(s, re.compile(s["pattern"], re.IGNORECASE))
                    for s in signatures if s.get("pattern")]
        findings: list[Finding] = []
        for rel in target.iter_files():
            sigs = [(s, rx) for s, rx in compiled if globs_ok(rel, s)]
            if not sigs:
                continue
            text = target.read_text(rel)
            if text is None:
                continue
            for s, rx in sigs:
                m = rx.search(text)
                if m:
                    findings.append(Finding(
                        signature_id=s["id"], category=s["category"],
                        severity=Severity.parse(s["severity"]), path=rel,
                        description=s["description"], remediation=s.get("remediation", "manual"),
                        line=text.count("\n", 0, m.start()) + 1,
                        evidence=evidence(text, m.start(), m.end()), vector=s["category"]))
        return findings
