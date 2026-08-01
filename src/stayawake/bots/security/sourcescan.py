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


# A self-describing inline asset (image/font/media data-URI). Stripped before the density
# and escape-run analysis so a legitimate `data:<mime>;base64,` blob does not inflate a
# line's length/entropy. (base64 blobs are no longer a standalone signal — see #1212.)
_DATA_URI = re.compile(r"data:[\w.+-]+/[\w.+-]+;base64,[A-Za-z0-9+/]+={0,2}", re.IGNORECASE)

# A JS string-reassembly seam: a closing quote, a `+` (concat) OR `,` (array element)
# separator, an opening quote — any whitespace/newlines between. Collapsing it rejoins
# `"\\x41" + "\\x42"` AND `["\\x41","\\x42"].join("")` into one run. Only quote-SEP-quote
# seams match, so a `+` inside a chunk, arithmetic `a + b`, a `["x", host]` array with a
# variable, and a list separator in prose are all untouched. The downstream escape-run gate
# (48+ run AND decoded byte-range AND entropy) is what keeps this FP-safe: reassembling a
# legit string array that carries no dense escape run trips nothing.
_CONCAT_SEAM = re.compile(r"['\"]\s*[,+]\s*['\"]")


def _dechunk(s: str) -> str:
    """Collapse JS string-reassembly seams so a payload split into quoted chunks
    (`"aaa" + "bbb"` OR `["aaa","bbb"].join("")`) is rejoined into one run before the
    blob/escape detectors see it. Cheap; a no-op on text with no quote-SEP-quote seams."""
    return _CONCAT_SEAM.sub("", s)
