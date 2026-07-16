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
  * dynamic-exec sinks            — eval(, new Function(, atob(, fromCharCode, the
    require-hijack global['!'], and reflective `x['constructor'](…)` Function-
    constructor smuggling (name-agnostic catch for a renamed decoder, #1053; the
    `new …` clone idiom is carved out): code that turns decoded bytes back into
    execution.
  * long base64 blob              — a single >=120-char [A-Za-z0-9+/=] run that is
    not already plain text (most real code has spaces/punctuation breaking it up).
  * concat/escape-encoded blob    — the SAME payload split into quoted chunks
    (`"a"+"b"+…` or `["a","b"].join("")`) or written as a dense byte-range, high-
    entropy `\\xNN`/`\\uNNNN` escape run; caught by normalizing the reassembly seams
    away and re-testing the reassembled content (#1053). Residual boundaries:
    template-literal `${a}${b}` reassembly (chunks live in variables) and `.concat`
    via non-quote args are not statically reassembled.
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

Build-artifact blind spot (deliberate; see docs/SECURITY_ARCHITECTURE.md → "Provenance is
not trust"). This heuristic is suppressed on generated/build/minified paths
(`is_generated_context`), because minification there IS obfuscation and flagging it would be
all false positives. RESIDUAL: a payload minified into a legitimate-looking bundle can be
statistically indistinguishable from a normal bundle and evade content detection. `saw`'s
durable guarantee is therefore on HAND-AUTHORED SOURCE plus git-history / evil-merge
corroboration — the point before a payload is baked into a post-build artifact — not on the
compiled output. This is a content decision, not a provenance one: `saw` never treats a
target's SLSA / PEP-740 attestation as trust; provenance attests the build, not the source. An
opt-in `scan_build_outputs` mode (analyze_file `constructs_only=True`) runs ONLY the self-evident
obfuscation-construct checks (charcode array / exec sink / base64 / escape run) on build outputs at
`heuristic` confidence as an inspection aid — it does not close the residual (a construct-free
minified payload still evades it).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

# A numeric array literal of >=8 elements, decimal or hex — the charcode/byte shuffler.
_NUM_ARRAY = re.compile(r"\[\s*(?:0x[0-9a-fA-F]+|\d{1,3})\s*(?:,\s*(?:0x[0-9a-fA-F]+|\d{1,3})\s*){7,}\]")
# Dynamic-execution sinks that turn decoded bytes back into running code. IGNORECASE-safe forms
# only (constructs with no common case-variant collision); the case-SENSITIVE reflective forms live
# in _REFLECTIVE_EXEC below. Beyond the classic eval/Function/atob/fromCharCode: vm's
# run-in-THIS-context (running code in the current global — a strong signal, and NOT a lodash
# method, unlike bare `runInContext`), and a Reflect apply/construct whose target is the eval or
# Function global. Surfaced as a HEURISTIC obfuscation verdict (SUSPICIOUS).
_EXEC_SINK = re.compile(
    r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*[\"']|\batob\s*\(|"
    r"String\s*[.\[]\s*[\"']?fromCharCode|global\s*\[\s*['\"]!['\"]\s*\]\s*=|"
    r"\brunInThisContext\s*\(|"
    r"\bReflect\s*\.\s*(?:apply|construct)\s*\(\s*(?:eval|Function)\b",
    re.IGNORECASE,
)
# One reflective access to the `constructor` property — via a dot OR a bracket-string key.
_CTOR_ACCESS = r"(?:\.\s*constructor\b|\[\s*[\"']constructor[\"']\s*\])"
# Reflective sinks the literal set misses, kept CASE-SENSITIVE on purpose (the real globals are
# `eval`/`Function`, the keyword is `constructor`; a lowercase `function` key is DATA, and a
# wrong-cased `SETTIMEOUT` is non-functional). Each requires a CALL / global position so an ordinary
# lookup or member method is never mistaken for an exec (the FP fixes the adversarial pass found):
#   • a dangerous global reached through a computed string key AND CALLED — `x['eval'](…)` — hides
#     WHICH global runs (a bare `handlers['Function']` registry lookup is NOT flagged);
#   • a DOUBLE constructor access then a call (`…constructor…constructor(`) — the constructor of the
#     constructor is the Function global → arbitrary code, in any dot/bracket mix; always Function,
#     so unlike the single-constructor clone below it needs no `new`-carve-out;
#   • a GLOBAL timer given a STRING/template body — `set(Timeout|Interval)('code', …)` — the
#     deprecated eval-form. The `(?<![.\w$])` keeps it to the global, so a member
#     `client.setTimeout('30s')` / `job.setInterval(cron)` duration setter is NOT flagged.
# Still not a full closure: a split-token/runtime-built key evades any token check; the durable
# lever is the Tier-2 density anomaly.
_REFLECTIVE_EXEC = re.compile(
    r"\[\s*[\"'](?:eval|Function)[\"']\s*\]\s*\("
    r"|" + _CTOR_ACCESS + r"\s*" + _CTOR_ACCESS + r"\s*\("
    r"|(?<![.\w$])set(?:Timeout|Interval)\s*\(\s*[\"'\x60]")
# Reflective Function-constructor smuggling via a SINGLE bracket-string key: reaches the Function
# constructor name-agnostically, so the worm's exec step (#1053) survives renaming the literal
# `sfL`/`_$_`/`global` fingerprints. Gated apart from _EXEC_SINK (see _has_exec_sink) so we carve
# out the one broad benign collision: the polymorphic same-type clone (a `new`-prefixed reflective
# constructor) used by value objects / ORM entities / immutable records. The worm NEVER prefixes
# with `new`, so excluding that drops the FP with zero loss. Plain `.name` access (no call) never
# matches — the arm requires `]` immediately followed by `(`.
_CONSTRUCTOR_EXEC = re.compile(r"\[\s*[\"']constructor[\"']\s*\]\s*\(")
# `new <ident/member-chain>` immediately before the bracket. The tight `[\w$.)\]]` class
# (no space/comma/`(`) means only a direct `new a.b['constructor'](` is excluded; a
# comma/whitespace splice like `new Date(), x['constructor'](p)` still flags.
_NEW_CLONE_PREFIX = re.compile(r"\bnew\s+[\w$.)\]]*\s*$")


def _has_exec_sink(s: str, strict: bool = False) -> bool:
    """True if `s` contains a dynamic-execution sink: any literal `_EXEC_SINK` construct, a
    case-sensitive `_REFLECTIVE_EXEC` form (computed-key access to a dangerous global, or a
    double-constructor Function reach), or a SINGLE reflective bracket-constructor call that is
    NOT a `new`-prefixed polymorphic clone (the benign idiom the worm never uses). Every
    single-constructor occurrence is checked, so a `new`-clone earlier can't mask a real sink later.

    `strict=True` DROPS the `new`-clone carve-out — every single bracket-constructor call counts.
    This is for gates that must not KEEP a possibly-hostile reflective constructor (e.g. deciding a
    surgically-excised file is benign enough to auto-clean): there, deferring on the benign idiom is
    a safe false-positive, whereas trusting it could pass an RCE hidden in kept code."""
    if _EXEC_SINK.search(s) or _REFLECTIVE_EXEC.search(s):
        return True
    return any(
        strict or not _NEW_CLONE_PREFIX.search(s[max(0, m.start() - 48):m.start()])
        for m in _CONSTRUCTOR_EXEC.finditer(s)
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

# ── Wrap/concat-resistant payload-at-rest detection (#1053 Tier-2 hardening) ──────
# The blob/array detectors above key on a long UNBROKEN run, which an attacker defeats
# two ways without changing the payload: (A) splitting it into short quoted chunks joined
# by `+` (`"aaa" + "bbb"`), whose quote/plus/space seams break the run; and (B) encoding it
# as a dense run of \xNN/\uNNNN escapes decoded at runtime (Buffer.from / fromCodePoint),
# which carries no [A-Za-z0-9+/] run at all. Both are reversible by NORMALIZING the seams
# away, then re-testing the reassembled content — what these two helpers add. Escape runs
# are tested on the de-chunked form too, so a chunked escape payload is reassembled first.

# A JS string-reassembly seam: a closing quote, a `+` (concat) OR `,` (array element /
# .concat arg) separator, an opening quote — any whitespace/newlines between. Collapsing it
# rejoins `"aaa" + "bbb"` AND `["aaa","bbb"].join("")` (the canonical obfuscator string-
# array primitive) into one run. Only quote-SEP-quote seams match, so base64 `+` inside a
# chunk, arithmetic `a + b`, a `["x", host]` array with a variable, and a list separator
# in prose are all untouched. The downstream >=120-char + 4.5-bit blob gate is what keeps
# this false-positive-safe: reassembling a legit short/low-entropy array trips nothing.
_CONCAT_SEAM = re.compile(r"['\"]\s*[,+]\s*['\"]")

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


def _dechunk(s: str) -> str:
    """Collapse JS string-reassembly seams so a payload split into quoted chunks
    (`"aaa" + "bbb"` OR `["aaa","bbb"].join("")`) is rejoined into one run before the
    blob/escape detectors see it. Cheap; a no-op on text with no quote-SEP-quote seams."""
    return _CONCAT_SEAM.sub("", s)


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


def analyze_file(text: str, ext: str = "", constructs_only: bool = False) -> ObfuscationVerdict:
    """Line-AGNOSTIC, baseline-free obfuscation verdict for a whole hand-authored
    source/config file (G4). Run on the RAW concatenated content so a payload that is
    SPLIT/WRAPPED across many <2000-char lines — which defeats the formatting-keyed
    long-line rule — is still caught.

    Two tiers, mirroring analyze_delta:
      1) self-evidently executable obfuscation (charcode/byte array, dynamic-exec sink,
         long base64 blob — including one reassembled from concat-chunked chunks or a
         dense escape-encoded run) — sufficient on its own, line-independent.
      2) a corroborated whole-file minification+entropy anomaly: the file carries an
         outlier-long line AND a dense packed region that dominates it AND the whole
         file reads as high-entropy. This is the in-file analogue of analyze_delta's
         "spike vs baseline": a hand-authored module is neither this dense nor this
         random, so the conjunction is what keeps it FP-free.

    Caller is responsible for context-scoping (skip is_generated_context paths) and
    for restricting to authored extensions; this function judges content only.

    `constructs_only=True` runs ONLY the self-evident construct checks (the charcode/byte array,
    dynamic-exec sink, and base64/escape-blob detectors above) and skips the whole-file
    density/entropy heuristic below. This is the opt-in build-output mode (`scan_build_outputs`):
    on a generated/minified path density IS expected and would be all false positives, but a
    self-evident construct (a charcode array, an exec sink, a base64/escape blob) is still worth
    surfacing as a heuristic signal. Never used on hand-authored source, where the whole-file
    density heuristic is the durable lever.
    """
    body = text or ""
    if not body.strip():
        return ObfuscationVerdict(False, "")

    # Tier 1 — self-evident constructs over the RAW content (never splitlines, so a
    # wrapped charcode array / base64 blob spanning line breaks is still seen).
    flat = body.replace("\n", "").replace("\r", "")
    if _NUM_ARRAY.search(flat):
        return ObfuscationVerdict(True, "charcode/byte numeric-array literal (string shuffler)")
    # Search the raw body AND the newline-flattened form so an exec sink wrapped
    # across line breaks (`sfL['constructor']\n(decoded)`) is still seen.
    if _has_exec_sink(body) or _has_exec_sink(flat):
        return ObfuscationVerdict(True, "dynamic-exec sink (eval/Function/atob/fromCharCode/constructor)")
    deassetted = _DATA_URI.sub("", flat)
    if _has_b64_payload(deassetted):
        return ObfuscationVerdict(True, "long unbroken base64 blob")
    # A+B (#1053): reassemble concat-chunked payloads, then re-test for a base64 blob or a
    # dense escape-encoded byte run — both survive the attacker splitting/encoding the
    # payload to dodge the unbroken-run detectors above (the merged-PR Tier-2 hardening).
    dechunked = _dechunk(deassetted)
    if _has_b64_payload(dechunked):
        return ObfuscationVerdict(True, "reassembled chunked base64 blob (string-concat splitting)")
    if _escape_run(dechunked):
        return ObfuscationVerdict(True, "dense escape-encoded byte payload (\\xNN/\\uNNNN run)")

    if constructs_only:
        # Build-output mode: stop here — skip the whole-file density heuristic below (density is
        # expected in a bundle, so running it there would be all false positives).
        return ObfuscationVerdict(False, "")

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
    if _has_exec_sink(text):
        return ObfuscationVerdict(True, "dynamic-exec sink (eval/Function/atob/fromCharCode/constructor)")
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
