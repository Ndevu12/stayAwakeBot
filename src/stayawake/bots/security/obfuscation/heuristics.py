#!/usr/bin/env python3
"""Whole-file obfuscation HEURISTICS — density / entropy / escape-run / minification, and the
context-aware suppression predicate.

Single responsibility: the corroborated (never self-evident) signals that a chunk of hand-authored
source is packed/encoded payload — a dense escape-encoded byte run, a whole-file minification+entropy
anomaly — plus `is_generated_context` (the single source of truth for "obfuscation is EXPECTED here"
paths) and the authored-extension set. The self-evident exec-sink constructs live in `execsink`; the
shared text primitives (entropy, data-URI, de-chunk) live in `sourcescan`; the public entry points
that compose these live in `entry`.
"""
from __future__ import annotations

import re

from stayawake.bots.security.sourcescan import _shannon


# ── Wrap/concat-resistant escape-payload-at-rest detection (#1053 Tier-2 hardening) ──
# A payload encoded as a dense run of \xNN/\uNNNN escapes decoded at runtime (Buffer.from /
# fromCodePoint) can dodge the escape-run detector by splitting into short quoted chunks
# joined by `+`/`,` (`"\\x41\\x42" + "\\x43…"`), whose quote/sep/space seams break the run.
# _dechunk normalizes those seams away so the escape-run test sees the reassembled content.
# (base64 reassembly is no longer tested — a base64 blob is benign data regardless of
# splitting, #1212 — so _dechunk now serves ONLY the escape-run arm.)

# A contiguous run of >= _MIN_ESCAPE_RUN numeric escapes (hex byte, BMP unicode, unicode
# code-point, or 3-digit octal). Length alone is NOT decisive (a 12-emoji row is 24 \uXXXX
# surrogate escapes; a crypto/magic-byte fixture is a short \xNN run), so _escape_run also
# applies a decoded byte-range + entropy gate — see there. 48 is the floor: above a
# 12-emoji row and a 32-byte KAT vector, far below any real escape-encoded loader (hundreds
# to thousands of bytes).
_MIN_ESCAPE_RUN = 48
_ESCAPE_RUN = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}|\\[0-3][0-7]{2})"
    r"{%d,}" % _MIN_ESCAPE_RUN
)
# Single-escape capture (one alternative group populated per match) for decoding a run.
_ESCAPE_TOKEN = re.compile(
    r"\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\([0-3][0-7]{2})")
# A real escape-encoded payload decodes to BYTES (0-255) with high entropy. Benign runs
# that clear the length bar do not: emoji/CJK/combining-mark tables decode to codepoints
# >255 in a narrow Unicode block, and structured magic-byte/file headers are low-entropy.
_ESCAPE_BYTE_FRAC = 0.8        # >=80% of decoded values must be in byte range (<=255)
_ESCAPE_MIN_ENTROPY = 4.5      # decoded-value entropy, mirroring the base64-blob gate


def _decode_escapes(run: str) -> list[int]:
    """Decode an escape run to its numeric values (hex byte, code-point, BMP unit, octal)."""
    out: list[int] = []
    for hx, ucp, u4, oc in _ESCAPE_TOKEN.findall(run):
        if hx:
            out.append(int(hx, 16))
        elif ucp:
            out.append(int(ucp, 16))
        elif u4:
            out.append(int(u4, 16))
        elif oc:
            out.append(int(oc, 8))
    return out


def _escape_run(s: str) -> bool:
    """True if `s` carries a contiguous run of >= _MIN_ESCAPE_RUN numeric escapes that
    decode to a high-entropy BYTE payload. The byte-range + entropy gate separates a packed
    worm payload (0-255 bytes, high entropy) from benign runs that merely clear the length
    bar: emoji/CJK/combining-mark tables (codepoints >255, narrow blocks) and structured
    magic-byte/file-header fixtures (low entropy). Every run is checked, so a benign run
    earlier in the file cannot mask a real payload later. Residual (documented): a >=48-byte
    high-entropy crypto KAT vector written as \\xNN is byte-range + high-entropy and stays a
    (rare, medium-severity, human-triageable) finding."""
    for m in _ESCAPE_RUN.finditer(s):
        vals = _decode_escapes(m.group(0))
        if not vals:
            continue
        byte_frac = sum(1 for v in vals if v <= 0xFF) / len(vals)
        if byte_frac >= _ESCAPE_BYTE_FRAC and _shannon("".join(map(chr, vals))) >= _ESCAPE_MIN_ENTROPY:
            return True
    return False


# Minification: a single introduced line at/above this length in a file whose
# baseline lines were comfortably shorter. Kept well under the 2000-char long-line
# rule so a split/wrapped payload (G4) that dodges that rule is still caught here.
_MINIFIED_LINE = 400
_BASELINE_TYPICAL_MAX = 200  # a normally-formatted source file's lines fit easily under this

# Entropy: payload-grade randomness, AND clearly above the file's own baseline.
_ENTROPY_ABS = 4.3           # bits/char; English prose ~4.0-4.5, but combined with the
_ENTROPY_DELTA = 0.8         # delta-vs-baseline gate this only fires on packed/encoded text



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
    # THIRD-PARTY INSTALLED CODE — node_modules (npm) and site-packages (a Python venv). Vendored
    # dependency code, where a package legitimately ships a minified `.js`/data blob → the density
    # heuristic would false-positive. Suppresses ONLY that heuristic (and the whitespace/oversized-line
    # corroborators); the CONFIRMED loader-fingerprint tier is ungated and STILL scans here, so a novel
    # or off-manifest malicious file in a venv is still caught (the InstalledPackageAudit adds identity +
    # RECORD-tamper on top). Structural, not a name-only exclusion: nothing here is pruned from traversal.
    r"node_modules/|site-packages/|vendor/|third[_-]?party/|"
    # BUILD OUTPUT DIRS — a deliberate build-artifact trust decision (NOT provenance): in a
    # compiled bundle minification IS obfuscation, so the density heuristic here would be all
    # false positives. A payload minified into such a bundle is the documented residual (see the
    # module docstring). Some of these are ALSO pruned at traversal in ScanOptions.exclude_dirs.
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
