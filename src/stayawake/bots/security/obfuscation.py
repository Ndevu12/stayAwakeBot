#!/usr/bin/env python3
"""Context-aware obfuscation analysis for a *delta* of source text.

Single responsibility: decide whether a chunk of newly-introduced text in a
hand-authored source file is obfuscated/packed payload, as opposed to ordinary
hand-written code. The detector is deliberately delta-scoped: it judges ONLY the
lines an edit introduced (e.g. the lines a merge slipped past review), compared
against a *baseline* of the file's pre-edit text. That comparison is what makes a
low-false-positive verdict possible — "this file suddenly became dense/minified"
is a far stronger signal than any absolute threshold on a whole file.

No I/O, no git, no regex catalogue duplication: callers pass in plain strings.

Why these particular signals (each independently sufficient is too aggressive, so
we require either a *self-evidently executable* obfuscation construct OR a
*corroborated* density/entropy anomaly):

  * charcode / hex numeric arrays  — `[104,116,116,112,...]`, `[0x68,0x74,...]`
    feeding String.fromCharCode / apply: the canonical Shai-Hulud string shuffler
    and the generic "build a string from numbers so no literal is greppable" trick.
  * dynamic-exec sinks            — eval(, new Function(, atob(, Function(, the
    require-hijack global['!']: code that turns decoded bytes back into execution.
  * long base64 blob              — a single >=120-char [A-Za-z0-9+/=] run that is
    not already plain text (most real code has spaces/punctuation breaking it up).
  * minification spike            — the introduced text is one (or few) very long
    lines AND the file's baseline was normally-formatted (short lines): a
    previously hand-formatted file does not legitimately gain a 2 KB single line
    in a merge/conflict resolution.
  * entropy spike                 — Shannon entropy per char of the introduced
    text is both high in absolute terms AND markedly above the file baseline:
    packed/encoded payload looks random; prose and code do not.

The verdict requires a dynamic-exec sink, OR a charcode/hex array, OR a base64
blob, OR (minification spike AND entropy spike together). A lone high-entropy or
lone long-line signal is NOT enough — that is exactly the benign "long config
value" / "generated data line" shape, and is left to corroborate elsewhere.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

# A numeric array literal of >=8 elements, decimal or hex — the charcode/byte shuffler.
_NUM_ARRAY = re.compile(r"\[\s*(?:0x[0-9a-fA-F]+|\d{1,3})\s*(?:,\s*(?:0x[0-9a-fA-F]+|\d{1,3})\s*){7,}\]")
# Dynamic-execution sinks that turn decoded bytes back into running code.
_EXEC_SINK = re.compile(
    r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*[\"']|\batob\s*\(|"
    r"String\s*[.\[]\s*[\"']?fromCharCode|global\s*\[\s*['\"]!['\"]\s*\]\s*=",
    re.IGNORECASE,
)
# A long unbroken base64-ish run not already broken up by code/prose punctuation.
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
# A self-describing inline asset (image/font/media data-URI). A base64 blob that is the
# payload of a `data:<mime>;base64,` URI is a legitimate inlined asset, not obfuscated
# code — so we exclude those runs before the base64-blob trigger to avoid that FP.
_DATA_URI = re.compile(r"data:[\w.+-]+/[\w.+-]+;base64,[A-Za-z0-9+/]+={0,2}", re.IGNORECASE)
# Minimum Shannon entropy a matched base64-blob run must itself carry to count as an
# encoded payload. A real base64 blob is ~5.5-6.0 bits/char (uniform over 64 symbols);
# a long *low-entropy* run that happens to be all [A-Za-z0-9+/] — e.g. a repeated-char
# placeholder/path segment (`token=xxxxxxxx…`) or a single-token long URL — is NOT an
# encoded payload and must not trip the blob trigger. This gate closes the long-URL FP
# (G5) without weakening detection of genuine base64 (which clears it by a wide margin).
_B64_BLOB_MIN_ENTROPY = 4.5

# Minification: a single introduced line at/above this length in a file whose
# baseline lines were comfortably shorter. Kept well under the 2000-char long-line
# rule so a split/wrapped payload (G4) that dodges that rule is still caught here.
_MINIFIED_LINE = 400
_BASELINE_TYPICAL_MAX = 200  # a normally-formatted source file's lines fit easily under this

# Entropy: payload-grade randomness, AND clearly above the file's own baseline.
_ENTROPY_ABS = 4.3           # bits/char; English prose ~4.0-4.5, but combined with the
_ENTROPY_DELTA = 0.8         # delta-vs-baseline gate this only fires on packed/encoded text


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ── Context-aware suppression (the single source of truth) ───────────────────────
# Paths where obfuscation/minification is EXPECTED, so dense/packed content is NOT
# anomalous: vendored caches, generated bundles, source maps, minified assets. A
# hand-authored *.config.* or a normal source file is deliberately NOT here — there
# obfuscation is anomalous and must be flagged. core.git imports this so the merge
# corroborator and the whole-file matcher share ONE predicate and never drift.
_GENERATED_PATH = re.compile(
    # Two arms, joined by `|`:
    #  (1) DIRECTORY / slash-anchored segments — must sit at a path-component boundary
    #      so `myvendor/` etc. do not match a partial word.
    #  (2) FILENAME tokens (.min.js, .map, .generated., .pb.js, …) — these are suffix/
    #      infix markers on the basename and must match ANYWHERE in the name, including
    #      mid-filename (`gql.generated.ts`, `app.min.js`) where no `/` precedes the token.
    r"(?:(?:^|/)("
    r"\.yarn/(?:cache|releases|unplugged)/|"
    r"node_modules/|vendor/|third[_-]?party/|"
    r"dist/|build/|out/|coverage/|storybook-static/|\.output/|\.svelte-kit/|\.nuxt/|\.next/|"
    r"generated/|__generated__/|"
    # Machine-generated dependency lockfiles (exact basenames only — NOT all *.json/*.yaml).
    # Their content is a single tool-emitted blob that routinely carries multi-kilobyte
    # lines (integrity hashes, resolved URLs); obfuscation there is EXPECTED, and they are a
    # prime `-X theirs` conflict-remerge surface, so the obfuscation corroborator must be
    # suppressed. The `(^|/)` anchor keeps these at a path-component boundary.
    r"package-lock\.json$|npm-shrinkwrap\.json$|yarn\.lock$|pnpm-lock\.yaml$|"
    r"composer\.lock$|Cargo\.lock$|poetry\.lock$|Gemfile\.lock$|go\.sum$|bun\.lockb$"
    r"))"
    r"|(?:"
    r"\.pnp\.[cm]?js$|\.min\.(?:js|css|mjs|cjs)$|\.map$|\.bundle\.js$|"
    r"\.generated\.|\.pb\.(?:js|ts)$|\.graphql\.(?:js|ts)$"
    r")",
    re.IGNORECASE,
)


def is_generated_context(path: str) -> bool:
    """True when `path` is a vendored/minified/generated location where obfuscation is
    EXPECTED (the context-aware-confidence lever). Callers suppress the obfuscation
    detector there so legitimate dense bundles never become findings."""
    return bool(_GENERATED_PATH.search(path))


# Extensions that are hand-authored source/config a human edits — where a packed/
# obfuscated blob is anomalous. Source maps (.map) and *.min.* are NOT here; those
# are caught (and suppressed) by is_generated_context instead. .json is excluded:
# a long minified JSON data line is a common benign shape and would need its own FP
# model; the worm's loader lives in executable modules, which this set covers.
_AUTHORED_OBFUSCATABLE_EXTS = {
    ".js", ".cjs", ".mjs", ".ts", ".mts", ".cts",
    ".jsx", ".tsx", ".vue", ".svelte",
}

# Whole-file minification: a payload wrapped onto lines each well under the 2000-char
# long-line threshold still produces lines FAR longer than a hand-authored file's
# typical line, AND a big block of such lines. We require BOTH an outlier-long line
# and that the dense region dominates the file, so an isolated legitimately-long line
# (a URL, a license header, one inlined constant) does not trip it on its own.
_OUTLIER_LINE = 400          # a single line this long in authored source is already unusual
_DENSE_LINE = 220            # lines at/above this count toward the "packed region"
_DENSE_CHARS_FRAC = 0.5      # packed region must be >=50% of the file's non-blank chars
# Packed/minified/encoded payload has almost no whitespace and very long unbroken
# token runs; natural-language prose (which also reaches ~4.3 bits/char) does NOT —
# prose is ~15-18% spaces with short words. These gates separate the two so a long
# repeated-prose template constant is not mistaken for packed code.
_MAX_PROSE_SPACE_FRAC = 0.07   # packed code is <7% whitespace; prose is far above this
_MIN_UNBROKEN_RUN = 200        # a >=200-char run with no whitespace is not human text


def _has_b64_payload(text: str) -> bool:
    """True if `text` contains a long unbroken base64-ish run that is ALSO high-entropy —
    i.e. a genuinely encoded blob, not a long low-entropy [A-Za-z0-9+/] run such as a
    repeated-char placeholder or a single-token URL. Callers must strip data-URIs first
    (legit inlined assets) before calling this."""
    for m in _B64_BLOB.finditer(text):
        if _shannon(m.group(0)) >= _B64_BLOB_MIN_ENTROPY:
            return True
    return False


def _longest_nonspace_run(s: str) -> int:
    best = run = 0
    for ch in s:
        if ch.isspace():
            run = 0
        else:
            run += 1
            if run > best:
                best = run
    return best


def analyze_file(text: str, ext: str = "") -> ObfuscationVerdict:
    """Line-AGNOSTIC, baseline-free obfuscation verdict for a whole hand-authored
    source/config file (G4). Run on the RAW concatenated content so a payload that is
    SPLIT/WRAPPED across many <2000-char lines — which defeats the formatting-keyed
    long-line rule — is still caught.

    Two tiers, mirroring analyze_delta:
      1) self-evidently executable obfuscation (charcode/byte array, dynamic-exec sink,
         long unbroken base64 blob) — sufficient on its own, line-independent.
      2) a corroborated whole-file minification+entropy anomaly: the file carries an
         outlier-long line AND a dense packed region that dominates it AND the whole
         file reads as high-entropy. This is the in-file analogue of analyze_delta's
         "spike vs baseline": a hand-authored module is neither this dense nor this
         random, so the conjunction is what keeps it FP-free.

    Caller is responsible for context-scoping (skip is_generated_context paths) and
    for restricting to authored extensions; this function judges content only.
    """
    body = text or ""
    if not body.strip():
        return ObfuscationVerdict(False, "")

    # Tier 1 — self-evident constructs over the RAW content (never splitlines, so a
    # wrapped charcode array / base64 blob spanning line breaks is still seen).
    flat = body.replace("\n", "").replace("\r", "")
    if _NUM_ARRAY.search(flat):
        return ObfuscationVerdict(True, "charcode/byte numeric-array literal (string shuffler)")
    if _EXEC_SINK.search(body):
        return ObfuscationVerdict(True, "dynamic-exec sink (eval/Function/atob/fromCharCode)")
    deassetted = _DATA_URI.sub("", flat)
    if _has_b64_payload(deassetted):
        return ObfuscationVerdict(True, "long unbroken base64 blob")

    # Tier 2 — corroborated whole-file minification anomaly (the split-line payload, and
    # G5: a loader-EVADED single long line in a real config file — packed/encoded content
    # is anomalous in hand-authored config regardless of the worm's loader fingerprint).
    # Strip inline-asset data-URIs FIRST: a `data:<mime>;base64,…` value is a legitimately
    # inlined asset, and its blob would otherwise dominate the density/entropy of an
    # otherwise-clean config line (the inline-data-URI FP). After removal, the residual
    # config text is judged on its own merits.
    de_body = _DATA_URI.sub("", body)
    lines = de_body.splitlines()
    longest = max((len(ln) for ln in lines), default=0)
    if longest < _OUTLIER_LINE:
        return ObfuscationVerdict(False, "")          # nothing line-dense enough to be packed
    nonblank_chars = sum(len(ln) for ln in lines if ln.strip())
    dense_chars = sum(len(ln) for ln in lines if len(ln) >= _DENSE_LINE)
    dense_frac = (dense_chars / nonblank_chars) if nonblank_chars else 0.0
    entropy = _shannon(de_body)
    # Structural payload-vs-prose discriminator: natural-language prose also reaches
    # ~4.3 bits/char, but it is whitespace-rich (~15-18% spaces, short words). Packed/
    # minified/encoded code is whitespace-poor with very long unbroken token runs.
    # Require BOTH a low space ratio AND a long unbroken run so a long prose template
    # constant is never mistaken for packed code.
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
    reason: str        # short, redaction-safe explanation for evidence strings

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
    if _NUM_ARRAY.search(text):
        return ObfuscationVerdict(True, "charcode/byte numeric-array literal (string shuffler)")
    if _EXEC_SINK.search(text):
        return ObfuscationVerdict(True, "dynamic-exec sink (eval/Function/atob/fromCharCode)")
    # Strip self-describing inline assets (image/font data-URIs) before the base64 test:
    # a `data:...;base64,...` payload is a legitimate inlined asset, not packed code.
    deassetted = _DATA_URI.sub("", text)
    if _has_b64_payload(deassetted):
        return ObfuscationVerdict(True, "long unbroken base64 blob")

    # 2) Corroborated density anomaly: a previously-formatted file that suddenly
    #    gains a very long single line that ALSO reads as high-entropy packed text.
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
