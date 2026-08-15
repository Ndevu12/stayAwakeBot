#!/usr/bin/env python3
"""Regex-over-text-files matcher."""
from __future__ import annotations

import re

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, evidence, globs_ok
from stayawake.bots.security.obfuscation.execsink import _has_exec_sink_beyond_decoding

# A signature may name a property its match must ALSO have before it counts. Data, not code: the rule
# lives in the signature file and adding one is an entry here plus an entry there.
#
# `exec-sink` exists because a construct can be both the malware's tell and ordinary vocabulary.
# `String.fromCharCode(127)` is how DEL is written, so every RFC 7230 token table matched a
# confirmed-tier loader fingerprint. What separates a string SHUFFLER from a character table is that
# the shuffler's output is executed.
CORROBORATORS = {
    "exec-sink": _has_exec_sink_beyond_decoding,
}

# NEAR the match, not anywhere in the file. Measured on the two vendored bundles that raised this:
# the nearest exec sink is >20,000 characters from the character table, while every real shuffler
# executes within 100-500. Whole-file co-presence is not corroboration — a minified bundle contains
# a sink somewhere by definition, which is why a first attempt at this fix still called both infected.
_CORROBORATION_RADIUS = 2_000


def _corroborated(name: str, text: str, start: int, end: int) -> bool:
    """Whether `text` carries the named property within reach of the match at [start, end)."""
    check = CORROBORATORS.get(name)
    if check is None:
        return True          # unknown name: fail toward reporting; the config test names the typo
    return bool(check(text[max(0, start - _CORROBORATION_RADIUS):end + _CORROBORATION_RADIUS]))


class ContentMatcher(Matcher):
    handles = "content"
    partitionable = True    # per-file (fired-set is per-file); verified #1325

    def scan(self, target, signatures):
        # IGNORECASE so trivial case-flips (let/LET, SFL vs sfL, 0X7F) don't evade.
        compiled = [(s, re.compile(s["pattern"], re.IGNORECASE))
                    for s in signatures if s.get("pattern")]
        findings: list[Finding] = []
        for rel in target.iter_files():
            sigs = [(s, rx) for s, rx in compiled if globs_ok(rel, s)]
            if not sigs:
                continue
            # read_source_windows streams the WHOLE body in overlapping windows so a payload buried
            # in the interior of an oversized source file is not skipped (#1145); a <=cap file yields
            # a single (0, text) window == read_text, so the common path is verdict-identical.
            # `fired` keeps today's "one finding per signature per file, at the earliest match":
            # windows are in file order, so the first window that matches a signature wins.
            fired: set[str] = set()
            for base_line, text in target.read_source_windows(rel):
                # Cheap literal pre-filter: a signature may declare a lowercase `prefilter` literal
                # that MUST be present for its (IGNORECASE) pattern to match. Rejecting on a substring
                # check before the regex is what makes scanning vendored trees (node_modules, etc.)
                # affordable — measured ~9x — and is verdict-identical (test_content_prefilter). Lower
                # lazily per window so a window with no prefiltered signature pays nothing.
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
                            evidence=evidence(text, m.start(), m.end()), vector=s["category"]))
        return findings
