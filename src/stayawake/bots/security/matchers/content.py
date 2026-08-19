#!/usr/bin/env python3
"""Regex-over-text-files matcher."""
from __future__ import annotations

import re

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, evidence, globs_ok
from stayawake.bots.security.obfuscation.execsink import _has_exec_sink_beyond_decoding

CORROBORATORS = {
    "exec-sink": _has_exec_sink_beyond_decoding,
}

_CORROBORATION_RADIUS = 2_000


def _corroborated(name: str, text: str, start: int, end: int) -> bool:
    """Whether `text` carries the named property within reach of the match at [start, end)."""
    check = CORROBORATORS.get(name)
    if check is None:
        return True          # unknown name: fail toward reporting; the config test names the typo
    return bool(check(text[max(0, start - _CORROBORATION_RADIUS):end + _CORROBORATION_RADIUS]))


class ContentMatcher(Matcher):
    handles = "content"
    partitionable = True

    def scan(self, target, signatures):
        compiled = [(s, re.compile(s["pattern"], re.IGNORECASE))
                    for s in signatures if s.get("pattern")]
        findings: list[Finding] = []
        for rel in target.iter_files():
            sigs = [(s, rx) for s, rx in compiled if globs_ok(rel, s)]
            if not sigs:
                continue
            fired: set[str] = set()
            for base_line, text in target.read_source_windows(rel):
                lowered: str | None = None
                for s, rx in sigs:
                    if s["id"] in fired:
                        continue
                    pf = s.get("prefilter")
                    if pf:
                        if lowered is None:
                            lowered = text.lower()
                        if pf not in lowered:
                            continue
                    m = rx.search(text)
                    if m and s.get("corroborate") and not _corroborated(
                            s["corroborate"], text, m.start(), m.end()):
                        continue
                    if m:
                        fired.add(s["id"])
                        findings.append(Finding(
                            signature_id=s["id"], category=s["category"],
                            severity=Severity.parse(s["severity"]), path=rel,
                            description=s["description"], remediation=s.get("remediation", "manual"),
                            line=base_line + text.count("\n", 0, m.start()) + 1,
                            evidence=evidence(text, m.start(), m.end()), vector=s["category"],
                            payload_window=True))
        return findings
