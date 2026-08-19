#!/usr/bin/env python3
"""Whole-file obfuscation heuristics, and the predicate that suppresses them in context.

These are corroborating signals: on their own they mark source as unusual, never as malicious, so
callers grade them below the self-evident constructs in `execsink`.
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

_MIN_ESCAPE_RUN = 48
_ESCAPE_RUN = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}|\\[0-3][0-7]{2})"
    r"{%d,}" % _MIN_ESCAPE_RUN
)
_ESCAPE_TOKEN = re.compile(
    r"\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\([0-3][0-7]{2})")
_ESCAPE_BYTE_FRAC = 0.8
_ESCAPE_MIN_ENTROPY = 4.5


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


_MINIFIED_LINE = 400
_BASELINE_TYPICAL_MAX = 200  # a normally-formatted source file's lines fit easily under this

_ENTROPY_ABS = 4.3
_ENTROPY_DELTA = 0.8



# ── Context-aware suppression (the single source of truth) ───────────────────────
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


_AUTHORED_OBFUSCATABLE_EXTS = {
    ".js", ".cjs", ".mjs", ".ts", ".mts", ".cts",
    ".jsx", ".tsx", ".vue", ".svelte",
}

_OUTLIER_LINE = 400
_DENSE_LINE = 220
_DENSE_CHARS_FRAC = 0.5      # packed region must be >=50% of the file's non-blank chars
_MAX_PROSE_SPACE_FRAC = 0.07
_MIN_UNBROKEN_RUN = 200


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
