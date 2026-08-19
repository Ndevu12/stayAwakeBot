#!/usr/bin/env python3
"""Public obfuscation entry points.

The whole-file and delta verdicts that callers outside this package use. Composes the checks in
`execsink`, `heuristics` and `taint` into one answer, so no caller has to know which signal fired.
"""
from __future__ import annotations

from dataclasses import dataclass

from stayawake.bots.security.sourcescan import _DATA_URI, _dechunk, _shannon
from stayawake.bots.security.taint import flow
from stayawake.bots.security.obfuscation.execsink import (
    _NUM_ARRAY, _has_exec_sink, _has_exec_sink_beyond_decoding, _is_charcode_shuffler)
from stayawake.bots.security.obfuscation.heuristics import (
    _escape_run, _longest_nonspace_run,
    _OUTLIER_LINE, _DENSE_LINE, _DENSE_CHARS_FRAC, _ENTROPY_ABS, _MAX_PROSE_SPACE_FRAC,
    _MIN_UNBROKEN_RUN, _MINIFIED_LINE, _BASELINE_TYPICAL_MAX, _ENTROPY_DELTA)


def _code_only(text: str) -> str:
    """`text` with COMMENTS removed and strings kept.

    A construct inside a comment does not run: `// never use eval() here` marked the file as an
    exec sink, as did commented-out code. Strings are deliberately kept — an obfuscator assembles
    `'ev'+'al'` in one, so blanking them would remove real signal. Length is preserved, so this
    stays interchangeable with the raw body."""
    return flow._scrub_comments_and_strings(text, scrub_strings=False)


def analyze_file(text: str, ext: str = "", constructs_only: bool = False) -> ObfuscationVerdict:
    """Line-AGNOSTIC, baseline-free obfuscation verdict for a whole hand-authored
    source/config file (G4). Run on the RAW concatenated content so a payload that is
    SPLIT/WRAPPED across many <2000-char lines — which defeats the formatting-keyed
    long-line rule — is still caught.

    Two tiers, mirroring analyze_delta:
      1) self-evidently executable obfuscation (charcode/byte array, dynamic-exec sink,
         or a dense escape-encoded byte run) — sufficient on its own, line-independent. A
         base64 blob (contiguous OR arrayed) is NOT here: it is ordinary data (JWT / API
         token / key array / asset), see #1212.
      2) a corroborated whole-file minification+entropy anomaly: the file carries an
         outlier-long line AND a dense packed region that dominates it AND the whole
         file reads as high-entropy. This is the in-file analogue of analyze_delta's
         "spike vs baseline": a hand-authored module is neither this dense nor this
         random, so the conjunction is what keeps it FP-free.

    Caller is responsible for context-scoping (skip is_generated_context paths) and
    for restricting to authored extensions; this function judges content only.

    `constructs_only=True` runs ONLY the self-evident construct checks (the charcode/byte array,
    dynamic-exec sink, and dense escape-run detectors above) and skips the whole-file
    density/entropy heuristic below. This is the opt-in build-output mode (`scan_build_outputs`):
    on a generated/minified path density IS expected and would be all false positives, but a
    self-evident construct (a charcode array, an exec sink, an escape-encoded byte run) is still
    worth surfacing as a heuristic signal. Never used on hand-authored source, where the whole-file
    density heuristic is the durable lever.
    """
    body = text or ""
    if not body.strip():
        return ObfuscationVerdict(False, "")

    code = _code_only(body)
    flat = code.replace("\n", "").replace("\r", "")
    if _is_charcode_shuffler(flat):
        return ObfuscationVerdict(True, "charcode/byte numeric-array literal (string shuffler)")
    # Search the raw body AND the newline-flattened form so an exec sink wrapped
    # across line breaks (`sfL['constructor']\n(decoded)`) is still seen.
    if _has_exec_sink_beyond_decoding(code) or _has_exec_sink_beyond_decoding(flat):
        return ObfuscationVerdict(True, "dynamic-exec sink (eval/Function/constructor/vm-runner)")
    # Decode→exec dropper — the ONE decode→exec-flow detector (see taint/): a baked encoded payload
    # variable-indirected form, leading arg) OR through a shell `-c` argument (`spawn('sh',['-c',d])`
    # the decode→exec FLOW is the dropper. Run on both the raw and newline-flattened views so a
    # decode wrapped across line breaks is still seen. Lazy import breaks the taint↔obfuscation cycle.
    from stayawake.bots.security.taint.analyzer import detect_dropper
    dropper = detect_dropper(body) or detect_dropper(flat)
    if dropper:
        return ObfuscationVerdict(True, dropper)
    deassetted = _DATA_URI.sub("", flat)
    # The dense escape-encoded byte run stays: unlike base64, a 48+ `\xNN`/`\uNNNN` run gated
    # on byte-range + entropy has no benign-data analogue (nobody writes a token/asset that
    if _escape_run(_dechunk(deassetted)):
        return ObfuscationVerdict(True, "dense escape-encoded byte payload (\\xNN/\\uNNNN run)")

    if constructs_only:
        # Build-output mode: stop here — skip the whole-file density heuristic below (density is
        return ObfuscationVerdict(False, "")

    de_body = _DATA_URI.sub("", body)
    lines = de_body.splitlines()
    longest = max((len(ln) for ln in lines), default=0)
    if longest < _OUTLIER_LINE:
        return ObfuscationVerdict(False, "")          # nothing line-dense enough to be packed
    nonblank_chars = sum(len(ln) for ln in lines if ln.strip())
    dense_chars = sum(len(ln) for ln in lines if len(ln) >= _DENSE_LINE)
    dense_frac = (dense_chars / nonblank_chars) if nonblank_chars else 0.0
    entropy = _shannon(de_body)
    space_frac = (sum(1 for c in de_body if c == " " or c == "\t") / len(de_body)) if de_body else 0.0
    unbroken = _longest_nonspace_run(de_body)
    packed_shape = space_frac <= _MAX_PROSE_SPACE_FRAC and unbroken >= _MIN_UNBROKEN_RUN
    if dense_frac >= _DENSE_CHARS_FRAC and entropy >= _ENTROPY_ABS and packed_shape:
        return ObfuscationVerdict(
            True,
            f"packed/minified content ({longest}-char line, "
            f"{dense_frac*100:.0f}% dense, {entropy:.1f} bits/char, "
            f"{unbroken}-char unbroken run)",
        )
    return ObfuscationVerdict(False, "")


@dataclass
class ObfuscationVerdict:
    obfuscated: bool
    reason: str

    def __bool__(self) -> bool:
        return self.obfuscated


def analyze_delta(introduced: str, baseline: str = "") -> ObfuscationVerdict:
    """Judge whether `introduced` (the newly-added text) is obfuscated payload,
    using `baseline` (the file's pre-edit text, may be empty for a brand-new file)
    to anchor the minification/entropy spikes.

    Returns an ObfuscationVerdict; truthy iff obfuscated. Designed so that ordinary
    code, prose, JSON, and normal conflict resolutions return False.
    """
    text = introduced or ""
    if not text.strip():
        return ObfuscationVerdict(False, "")

    # 1) Self-evidently executable obfuscation constructs — sufficient on their own.
    if _is_charcode_shuffler(text):
        return ObfuscationVerdict(True, "charcode/byte numeric-array literal (string shuffler)")
    if _has_exec_sink_beyond_decoding(text):
        return ObfuscationVerdict(True, "dynamic-exec sink (eval/Function/constructor/vm-runner)")
    # Decode→exec dropper introduced by the hunk — same ONE detector as analyze_file (leading-arg
    # decode→exec FLOW is. See taint/.
    from stayawake.bots.security.taint.analyzer import detect_dropper
    dropper = detect_dropper(text)
    if dropper:
        return ObfuscationVerdict(True, dropper)

    intro_lines = text.splitlines() or [text]
    longest_intro = max((len(ln) for ln in intro_lines), default=0)
    base_lines = baseline.splitlines() if baseline else []
    base_typical = max((len(ln) for ln in base_lines), default=0)

    minified_spike = (longest_intro >= _MINIFIED_LINE and base_typical <= _BASELINE_TYPICAL_MAX)

    intro_entropy = _shannon(text)
    base_entropy = _shannon(baseline) if baseline.strip() else 0.0
    entropy_spike = (
        intro_entropy >= _ENTROPY_ABS
        and (base_entropy == 0.0 or intro_entropy - base_entropy >= _ENTROPY_DELTA)
    )

    if minified_spike and entropy_spike:
        return ObfuscationVerdict(
            True,
            f"minified+high-entropy hunk ({longest_intro}-char line, "
            f"{intro_entropy:.1f} bits/char vs baseline {base_entropy:.1f})",
        )

    return ObfuscationVerdict(False, "")
