#!/usr/bin/env python3
"""Low-level source-text primitives shared by the obfuscation and taint detectors.

Single responsibility: the small, dependency-free text utilities BOTH `obfuscation` (whole-file
density/entropy analysis) and `taint` (decode→exec dropper flow) need — Shannon entropy, the
inline-asset data-URI matcher, and the string-reassembly de-chunker. Housing them here (below both
detectors, importing neither) is what lets `taint` stop reaching up into `obfuscation` for them:
the dependency now flows one way, `{obfuscation, taint} → sourcescan`. No I/O, no git.
"""
from __future__ import annotations

import math
import re


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_DATA_URI = re.compile(r"data:[\w.+-]+/[\w.+-]+;base64,[A-Za-z0-9+/]+={0,2}", re.IGNORECASE)

_CONCAT_SEAM = re.compile(r"['\"]\s*[,+]\s*['\"]")


def _dechunk(s: str) -> str:
    """Collapse JS string-reassembly seams so a payload split into quoted chunks
    (`"aaa" + "bbb"` OR `["aaa","bbb"].join("")`) is rejoined into one run before the
    blob/escape detectors see it. Cheap; a no-op on text with no quote-SEP-quote seams."""
    return _CONCAT_SEAM.sub("", s)
