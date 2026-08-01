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
    require-hijack global['!'], vm.runInNewContext/runInContext (incl. the
    `require('vm').runInContext` form, #1208), and reflective `x['constructor'](…)`
    Function-constructor smuggling (name-agnostic catch for a renamed decoder, #1053;
    the `new …` clone idiom is carved out): code that turns decoded bytes back into
    execution.
  * corroborated dynamic-exec (#1208 residual, TIGHTENED #1289) — the SCAN flags only the two
    precise shapes with no benign analogue: a `data:` JS-MIME AND base64-encoded `import(` (a
    concealed inline module; plaintext `data:…,code` stays clean), and a require-receiver command
    runner (`child_process`/`shelljs`) fed a decode. The BROAD arms — any non-literal `import(` or
    constructed `child_process` command — FP'd on every lazy-import / build script, so they no
    longer raise a finding; they are RETAINED only as the conservative remediation gate
    (`_has_exec_sink(strict=True)`), where over-refusal is safe. `require('vm').runInContext` and the
    nested decode→exec (`import(atob`, `execSync(Buffer.from`) are #1266 / _EXEC_SINK, not here.
    Heuristic → SUSPICIOUS.
  * obfuscated exec sinks (#1207) — what #1206 deliberately left open (split-token /
    indirect / light alias). Bounded same-quote string-concat fold (`'ev'+'al'` → `'eval'`)
    before the existing sink regexes; plus `(0, eval)(` / `(0, Function)(`, a
    `const e = eval; e(` binding-then-call, and `const k = 'eval'; g[k](` after fold.
    Heuristic → SUSPICIOUS. Hard residual: cross-statement dataflow beyond the light
    window, mixed-quote / template splits, and a renamed binding whose RHS is itself
    computed.
  * decode→exec dropper (#1266)   — a base64/hex DECODE (`Buffer.from(` / `atob(`) as the
    LEADING argument to a command / dynamic-module sink the exec-sink arm doesn't cover:
    `child_process` runners (execSync/execFile/spawn/fork), a dynamic `import(`, or
    `new Worker(`. The FLOW is the tell, not the encoded bytes (#1212) — neither half is a
    signal alone. Purely static: the recipe is matched in the text, never decoded or run.
  * encoded blob (base64/hex)      — NOT a signal ON ITS OWN (#1212). A >=120-char base64 run
    (or >=200-char hex run), contiguous OR reassembled from concat/array chunks, is ubiquitous
    benign DATA: JWTs, API tokens, SRI hashes, cert-pin / JWKS key arrays, crypto KAT vectors,
    hex keys, inlined assets. A lone blob is therefore never flagged. But a blob DECODED THROUGH A
    VARIABLE and then RUN — `const d = Buffer.from(p,'base64'); execSync(d)` — is the in-file
    dropper #1266's nested check misses and #1212's removal opened; it is flagged when a blob is
    present AND a decode result flows (in scope, one hop) into a command/`import(`/`Worker` sink
    (`_has_encoded_payload` + `_decode_var_into_exec`). The corroboration keeps a lone JWT / key /
    asset clean. Residual: a loader whose exec is in ANOTHER file, or reached by multi-hop
    reassignment (indistinguishable from a lone blob without cross-file/whole-program dataflow).
  * dense escape-encoded byte run  — a payload written as a contiguous >=48 run of
    `\\xNN`/`\\uNNNN` escapes decoding to high-entropy BYTES; caught after normalizing
    concat/array reassembly seams away (#1053). Unlike base64 this HAS no benign-data
    analogue (nobody writes a token/asset as an escape run), so the byte-range + entropy
    gate keeps it FP-safe. Residual boundaries: template-literal `${a}${b}` reassembly
    (chunks live in variables) and `.concat` via non-quote args are not reassembled.
  * minification spike            — the introduced text is one (or few) very long
    lines AND the file's baseline was normally-formatted (short lines): a
    previously hand-formatted file does not legitimately gain a 2 KB single line
    in a merge/conflict resolution.
  * entropy spike                 — Shannon entropy per char of the introduced
    text is both high in absolute terms AND markedly above the file baseline:
    packed/encoded payload looks random; prose and code do not.

The verdict requires a dynamic-exec sink, OR a charcode/hex array, OR a dense
escape-encoded byte run, OR an encoded blob whose decode flows into a sink, OR
(minification spike AND entropy spike together). A LONE encoded blob (base64/hex,
contiguous or arrayed), a lone high-entropy signal, and a lone long line are NOT
enough on their own — those are exactly the benign "embedded token / key array /
asset", "long config value", and "generated data line" shapes (#1212).

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
obfuscation-construct checks (charcode array / exec sink / escape run) on build outputs at
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
# dynamic-code runners — `runInThisContext` and `runInNewContext` (run code in the current /
# a fresh global; neither is a lodash method, so both are safe bare) and the vm-QUALIFIED
# receivers for `runInContext` (bare `runInContext` IS a lodash method — `_.runInContext()` —
# so it must carry a `vm.` OR `require('vm').` receiver to avoid that false positive; the
# `require('vm').runInContext` form is the #1208 gap the dotted `vm.` arm alone missed); and a
# Reflect apply/construct whose target is the eval or Function global. Surfaced as a HEURISTIC
# obfuscation verdict (SUSPICIOUS).
_EXEC_SINK = re.compile(
    r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*[\"']|\batob\s*\(|"
    r"String\s*[.\[]\s*[\"']?fromCharCode|global\s*\[\s*['\"]!['\"]\s*\]\s*=|"
    r"\brunInThisContext\s*\(|\brunInNewContext\s*\(|"
    r"\bvm\s*\.\s*runInContext\s*\(|"
    r"\brequire\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*[\"']vm[\"']\s*\)\s*(?:\?\s*)?\.\s*runInContext\s*\(|"
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
# Still not a full closure: a renamed/aliased sink beyond the light #1207 window, or a
# mixed-quote / template split, still evades; the durable lever is the Tier-2 density anomaly.
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

# ── #1207 obfuscated exec sinks (after #1206; orthogonal to #1208/#1266) ───────────
# Timeline: #1207 was filed ~5 min after #1206 as the deliberate residual tracker for
# forms no token check can see without a light de-obfuscation pass. #1266/#1208 later
# closed OTHER residuals (decode→exec, non-literal import, constructed child_process);
# they do NOT cover these. This block closes the COMMON obfuscator output only:
#
# 1) Bounded same-quote string-concat FOLD (`'ev'+'al'` → `'eval'`, `'con'+'structor'` →
#    `'constructor'`) so the existing reflective/literal sink regexes fire on the
#    reassembled token. Distinct from `_dechunk` (which STRIPS quotes for escape-run
#    reassembly). Mixed quotes / templates / `.concat(` are NOT folded — arms race.
#
# 2) Indirect call via the comma operator: `(0, eval)(x)` / `(0, Function)('…')` (and the
#    common `void 0` / `null` / `!0` left-hand variants). Babel's `(0, _mod.default)(x)`
#    stays clean — the RHS must be the bare `eval`/`Function` global.
#
# 3) Light alias: `const e = eval; e(x)` / `let F = Function; F('…')` — a binding whose RHS
#    is the bare global, then that binding CALLED within a short window.
#
# 4) Light runtime-built key (after fold): `const k = 'ev'+'al'; g[k](x)` → folded to
#    `const k = 'eval'; g[k](x)`. The `new …[k](` polymorphic-clone shape is carved out
#    (same gate as `_CONSTRUCTOR_EXEC`).
#
# Heuristic → SUSPICIOUS. Hard residual: dataflow past the window, mixed-quote splits,
# `const e = g['ev'+'al']; e(x)` (RHS not a bare global), Tier-2 density remains the
# durable lever.
_STR_CONCAT_FOLD = re.compile(
    r"(['\"])([^'\"\\\n]{0,64})\1\s*\+\s*\1([^'\"\\\n]{0,64})\1"
)
_INDIRECT_EVAL = re.compile(
    r"\(\s*(?:0|1|void\s+0|null|undefined|!0|!1)\s*,\s*(?:eval|Function)\s*\)\s*\("
)
_BIND_EVAL_FN = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:eval|Function)\b"
)
_BIND_DANGEROUS_KEY = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[\"'](?:eval|Function|constructor)[\"']"
)
_ALIAS_CALL_WINDOW = 240


def _fold_string_concats(s: str, max_passes: int = 24) -> str:
    """Collapse adjacent same-quote string concatenations (`'ev'+'al'` → `'eval'`) so the
    existing sink regexes see the reassembled token (#1207). Bounded chunk length (64) and
    pass count (24) keep this ReDoS/DoS-safe; a no-op on text with no quote-concat seams."""
    for _ in range(max_passes):
        ns = _STR_CONCAT_FOLD.sub(
            lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(1)}", s)
        if ns == s:
            return s
        s = ns
    return s


def _has_obfuscated_exec_forms(s: str) -> bool:
    """True if `s` (already fold-normalized) has an indirect / light-alias / runtime-key
    exec form from #1207. Call-required and `new`-clone-carved; Babel `(0, _mod.x)(` stays
    clean."""
    if _INDIRECT_EVAL.search(s):
        return True
    for m in _BIND_EVAL_FN.finditer(s):
        name = re.escape(m.group(1))
        window = s[m.end():m.end() + _ALIAS_CALL_WINDOW]
        if re.search(rf"(?<![\w$]){name}\s*\(", window):
            return True
    for m in _BIND_DANGEROUS_KEY.finditer(s):
        name = re.escape(m.group(1))
        window = s[m.end():m.end() + _ALIAS_CALL_WINDOW]
        for cm in re.finditer(rf"\[\s*{name}\s*\]\s*\(", window):
            prefix = window[max(0, cm.start() - 48):cm.start()]
            if _NEW_CLONE_PREFIX.search(prefix):
                continue
            return True
    return False


def _has_exec_sink(s: str, strict: bool = False) -> bool:
    """True if `s` contains a dynamic-execution sink: any literal `_EXEC_SINK` construct, a
    case-sensitive `_REFLECTIVE_EXEC` form (computed-key access to a dangerous global, or a
    double-constructor Function reach), a #1208 residual form (see `_has_corroborated_dynamic_exec`),
    a #1207 obfuscated form (split-token via concat-fold, indirect comma-call, light alias /
    runtime-key), or a SINGLE reflective bracket-constructor call that is NOT a `new`-prefixed
    polymorphic clone (the benign idiom the worm never uses). Every single-constructor occurrence is
    checked, so a `new`-clone earlier can't mask a real sink later.

    `strict=True` is the REMEDIATION gate mode (deciding a surgically-excised file is benign enough
    to auto-clean), and makes the whole check MORE conservative in two ways: (1) it DROPS the
    `new`-clone carve-out — every single bracket-constructor call counts; and (2) it enables the
    BROAD #1208 arms (any non-literal import / constructed child_process command) that are too
    FP-prone for a scan finding (#1289) but safe as a gate. In both, deferring on a benign shape is a
    safe false-positive, whereas trusting it could pass an RCE hidden in kept code."""
    # Fold first so `'ev'+'al'` becomes `'eval'` before every arm (including #1208 scrub).
    view = _fold_string_concats(s)
    if (_EXEC_SINK.search(view) or _REFLECTIVE_EXEC.search(view)
            or _has_corroborated_dynamic_exec(view, strict=strict) or _has_obfuscated_exec_forms(view)):
        return True
    return any(
        strict or not _NEW_CLONE_PREFIX.search(view[max(0, m.start() - 48):m.start()])
        for m in _CONSTRUCTOR_EXEC.finditer(view)
    )


# ── Decode-then-exec dropper (#1266) ──────────────────────────────────────────────
# The decode→exec DATA FLOW that #1212 stopped inferring from a bare base64 blob. base64
# alone is benign data; a DECODE call whose result is fed straight into a command / dynamic-
# module sink is the dropper. We match the FLOW textually — a decode call as the LEADING
# argument to the sink — so neither half is a signal on its own:
#   • decode  = `atob(` (also an _EXEC_SINK on its own) OR `Buffer.from(` (the Node decoder —
#     benign alone: decoding a JWT, an image, a hash; only running its result is the tell).
#     Matched by the call START, not the `'base64'` encoding arg, because the payload blob sits
#     BETWEEN `Buffer.from(` and its encoding arg and can be arbitrarily long (a bounded window
#     to the arg would be evaded by a big blob). Running a CONSTRUCTED buffer as a command /
#     module / worker is anomalous whatever the encoding (base64, hex, or a raw byte array that
#     spells a command) — so the call start is the right, robust anchor.
#   • sink    = the child_process-SPECIFIC command runners (execSync/execFile[Sync]/spawn[Sync]/
#     fork — a regex `.exec`/event `.spawn` has none of these names, so no collision), a dynamic
#     `import(`, or `new Worker(`. Bare `exec(` is deliberately NOT a sink: `regex.exec(buf)` is
#     an ordinary decode-then-match, not a command.
# Requiring the decode to be the sink's argument keeps this near-zero-FP: no legitimate code runs
# a Buffer/atob result as a shell command / module specifier / worker source. PURELY STATIC text
# match — nothing is ever decoded or executed. `\s*` between sink `(` and the decode is bounded
# (ReDoS-safe). RESIDUAL (still #1266): a decode assigned to a VARIABLE then passed to the sink
# (indirection), and a `data:` base64 URI dynamic import (`import('data:…;base64,'+p)`).
_DECODE = r"(?:atob\s*\(|Buffer\s*\.\s*from\s*\()"
_DECODE_INTO_EXEC = re.compile(
    r"\b(?:execSync|execFileSync|execFile|spawnSync|spawn|fork)\s*\(\s*" + _DECODE
    + r"|\bimport\s*\(\s*" + _DECODE
    + r"|\bnew\s+Worker\s*\(\s*" + _DECODE,
    re.IGNORECASE,
)

# ── #1208 residual (after #1206 + #1266), TIGHTENED per #1289 ──────────────────────
# Timeline: #1208 was filed ~5 min after #1206 as the deliberate residual tracker; #1266 then
# closed the DECODE→exec half (`import(atob`, `execSync(Buffer.from`). v0.1.17 closed the rest with
# two BROAD arms — any non-literal `import(x)`, any constructed `execSync(cmd + …)` — which #1289
# found FP-prone at near-zero precision: every React.lazy / `@/`-alias / i18n dynamic import and
# every build script (`execSync(`npm run ${task}`)`) fires. A bare dynamic import or a runtime-built
# command is NOT, on its own, separable from ordinary code (same wall as #1185) — so those broad
# arms must not raise a SCAN finding.
#
# The fix is a SENSITIVITY SPLIT keyed on `_has_exec_sink`'s existing `strict` flag, because the two
# callers want opposite things:
#   • the SCAN verdict (strict=False) wants PRECISION — only shapes with no benign analogue, so a
#     lazy-import / build script never becomes a SUSPICIOUS finding. TIGHT arms only:
#       2a) a `data:` EXECUTABLE-module dynamic import — an inline (java|ecma)script / base64 module
#           passed to `import(`. No benign analogue; the signal lives INSIDE the specifier string so
#           this arm runs on a COMMENT-scrubbed view (strings KEPT — a full string scrub blanks it).
#       2b) a require-RECEIVER child_process runner fed a DECODE — `require('cp').exec(atob(x))` — the
#           form #1266's bare-name set misses. Full comment+string scrub (module name blanked).
#       (`require('vm').runInContext` is in `_EXEC_SINK`; `import(atob(x))` is #1266's `_DECODE_INTO_EXEC`.)
#   • the REMEDIATION gate (strict=True) wants CONSERVATISM — "the kept code MIGHT dynamically exec,
#     so REFUSE to auto-clean." There an over-broad match is SAFE (defer to manual); a miss is not. So
#     the broad arms (bare non-literal import, any constructed child_process command) are KEPT, but
#     used ONLY under strict. Nothing is downgraded — the broad coverage moves to exactly the caller
#     where a false positive is the safe direction.
#
# Heuristic → SUSPICIOUS (informs; never CI-fails; never auto-remediates). Hard residual: a bare
# dynamic import / runtime-built command with no decode or data:-URI tell (deliberately NOT a scan
# finding — indistinguishable from legit lazy-load / build tooling), fully-indirect `const i=import`.
_CONSTRUCTED_ARG = (
    r"(?:"
    + r"[\"'][^\"'\n]{0,200}[\"']\s*\+"          # 'cmd' + …
    + r"|[A-Za-z_$][\w$]*\s*\+"                  # cmd + …
    + r"""|`[^`\n]{0,200}`\s*\+"""               # `cmd` + …
    + r"""|`[^`\n]{0,200}\$\{"""                 # `…${…}`
    + r")"
)
_DYNAMIC_IMPORT = re.compile(
    r"(?<![.\w$])import\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*(?:"
    # non-relative template with interpolation
    + r"""`(?!\./|\.\./)[^`\n]{0,200}\$\{"""
    # or any non-string / non-template / non-comment start (bare ident, call, …)
    # `(?=[^\s])` stops `\s*` backtracking onto a space before a string (webpack FP).
    + r"|(?=[^\s])(?![\"'`]|/\*)"
    + r")",
    re.IGNORECASE,
)
_CP_RUNNERS = r"(?:execSync|execFileSync|execFile|spawnSync|spawn|fork)"
_CONSTRUCTED_CP = re.compile(
    # Runner names are child_process-specific (no regex.exec collision). The
    # require('…').exec form uses a quoted-module wildcard so it still matches after
    # the comment/'/-string scrub blanks the module-name characters (quotes remain).
    r"(?<![.\w$])" + _CP_RUNNERS + r"\s*\(\s*" + _CONSTRUCTED_ARG
    + r"|\brequire\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*[\"'][^\"'\n]{1,64}[\"']\s*\)\s*"
    + r"(?:\?\s*)?\.\s*exec(?:Sync)?\s*\(\s*(?:" + _CONSTRUCTED_ARG + r"|" + _DECODE + r")",
    re.IGNORECASE,
)
# TIGHT arms (always on — precise enough for a SCAN finding, #1289).
# 2a) A `data:` URI that is a JS-MIME module AND base64-ENCODED, passed to `import(` — the inline
#     encoded stage-2 loader. BOTH gates matter (accuracy, FP-hunt):
#       • MIME must be (java|ecma)script — ESM only RUNS a JS-MIME data: import; a
#         `data:application/json;base64,…` module is inert DATA.
#       • it must be `;base64,`-ENCODED — a PLAINTEXT `data:text/javascript,export const x=1` import
#         is a documented, standards-blessed inline-module idiom (module-loader tests, REPL/playground
#         tools, Deno) whose code is READABLE, i.e. not obfuscation. Only the base64-encoded form is a
#         concealed payload. Requiring both keeps the readable inline-module case CLEAN.
#     Runs on a COMMENT-only scrubbed view (see `_has_corroborated_dynamic_exec`): the tell is INSIDE
#     the specifier string, which a full string-scrub would blank. Bounded lookaheads keep it linear.
_DATA_URI_IMPORT = re.compile(
    r"(?<![.\w$])import\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*['\"\x60]\s*data:"
    r"[^'\"\x60\n]{0,80}?(?:java|ecma)script[^'\"\x60\n]{0,40}?;base64,",
    re.IGNORECASE,
)
# 2b) A require-RECEIVER command runner fed a DECODE — `require('child_process').exec(atob(x))`,
#     `require('shelljs').execSync(Buffer.from(x))`. The bare-name #1266 set (`execSync(decode)`)
#     misses the `.exec` on a required module. The module is CONSTRAINED to real command runners
#     (child_process / shelljs) — a wildcard module FP'd on `require('./re').exec(Buffer.from(x))`
#     (RegExp.exec) and `require('./db').exec(<decoded SQL>)` (sqlite .exec). Runs on a
#     strings-KEPT (comment-only) scrub so the module name is visible; the decode arg is the tell.
_CP_METHOD = r"(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)"
_REQUIRE_CP_DECODE = re.compile(
    r"\brequire\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*['\"](?:node:)?(?:child_process|shelljs)['\"]\s*\)\s*"
    r"(?:\?\s*)?\.\s*" + _CP_METHOD + r"\s*\(\s*" + _DECODE,
    re.IGNORECASE,
)


# ── Variable-indirected decode→exec dropper (#1266 residual; restores the #1212 base64 arm,
#    TIGHTENED so it can never FP on a lone blob) ─────────────────────────────────────────────
# #1266's `_DECODE_INTO_EXEC` catches only a decode NESTED in the sink (`execSync(Buffer.from(…))`).
# It (and #1212's removal of the standalone base64 arm) leaves a real blind spot the user hit: a
# hardcoded base64 payload decoded through a VARIABLE and then run —
#     const p = '<blob>'; const d = Buffer.from(p, 'base64'); execSync(d);
# Neither half is a signal alone: the blob at rest is ubiquitous benign DATA (JWT / API token /
# SRI hash / cert-pin·JWKS key array / crypto KAT / inlined asset) — flagging it standalone is the
# exact #1212 FP that stays removed — and a bare decode is a normal JWT/asset read. The TELL is the
# two together: an encoded blob is present AND a decode result flows into a command/module/worker
# sink. So we RESTORE the encoded-blob check (deleted by #1212) but ONLY as a CORROBORATOR to the flow,
# never a standalone verdict. This also stays inside saw's baked-payload threat model: requiring a
# hardcoded blob means a `Buffer.from(networkInput); execSync(…)` runtime-RCE (no baked blob) is left
# to other tooling rather than false-alarming here.

# The encoded blob a decode→exec flow is corroborated against — RESTORED from #1212 as a
# corroborator only (see above); callers strip data-URIs first so an inline asset never corroborates.
# Two alphabets, because a payload can be baked as either:
#   • base64 — a >=120-char high-entropy [A-Za-z0-9+/] run (NOT a low-entropy placeholder / URL).
#   • hex    — a >=200-char run of hex digits. Hex maxes at ~4.0 bits/char (16 symbols), BELOW the
#     base64 4.5 gate, so it needs its own check or a `Buffer.from(p,'hex')` dropper is missed
#     (FN-hunt). The length floor (200 = 100 bytes) sits above a SHA-512 (128) / 3×SHA-256 (192)
#     hash so an embedded digest does not corroborate; a modest 3.5 entropy gate drops repeated-char
#     hex padding. Both are corroborators ONLY — never a standalone verdict (a lone key/hash is data).
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_B64_BLOB_MIN_ENTROPY = 4.5
_HEX_BLOB = re.compile(r"(?<![0-9a-fA-Fx])[0-9a-fA-F]{200,}(?![0-9a-fA-F])")
_HEX_BLOB_MIN_ENTROPY = 3.5


def _has_encoded_payload(text: str) -> bool:
    """True if `text` carries a baked base64 OR hex encoded blob (see `_B64_BLOB`/`_HEX_BLOB`). NOT a
    verdict on its own — the #1212 FP class (a mock JWT / a hex key is exactly this shape) — used
    ONLY to corroborate `_decode_var_into_exec`."""
    for m in _B64_BLOB.finditer(text):
        if _shannon(m.group(0)) >= _B64_BLOB_MIN_ENTROPY:
            return True
    for m in _HEX_BLOB.finditer(text):
        if _shannon(m.group(0)) >= _HEX_BLOB_MIN_ENTROPY:
            return True
    return False


# A base64/hex decode (`atob(` / `Buffer.from(`) ASSIGNED to a variable, whose name is captured so
# we can look for that variable flowing into a sink. Optional declaration keyword (const/let/var or a
# bare reassignment); `(?<![.\w$])` keeps a property write `obj.d =` and mid-identifier matches out;
# `(?!=)` rejects `==`/`===`/`=>` (comparison / arrow, not an assignment of the decode).
_DECODE_TO_VAR = re.compile(
    r"(?:(?:const|let|var)\s+)?(?<![.\w$])([A-Za-z_$][\w$]*)\s*=(?!=)\s*" + _DECODE
)
_INDIRECT_SINK_WINDOW = 300   # chars after the decode-assignment in which the sink must appear
_MAX_DECODE_VARS = 50         # cap the assignments scanned so a hostile file can't blow up the walk


# The decoded value reaches a sink as its LEADING arg used DIRECTLY — bare, or through a chain of
# METHOD CALLS (`d.toString('utf8').trim()`, a real decode idiom) — NEVER as a bare PROPERTY of it:
# `spawn(cfg.cmd, cfg.args)` / `import(mod.entry)` mean the variable is a structured config OBJECT,
# not raw decoded bytes, so a name collision there was a FP (FP-hunt). Tail = zero or more
# `.method(...)` calls then a `,` or `)`. A property access (`.cmd` with no `()`) breaks the chain.
_DECODED_ARG_TAIL = r"\s*(?:\.\s*[\w$]+\s*\([^)]*\))*\s*[,)]"
# A parameter list that BINDS names — `(params)` followed by `{` (function / method / class-method /
# `catch` body) or `=>` (arrow) — so we can tell a re-bound same-name (a collision) from the decoded
# var. A leading control-flow keyword (`if (cond) {` …) is excluded: it does NOT bind a name. The
# `{0,120}` bound keeps this linear on a hostile `(`-run (an unbounded `[^)]*` is O(n^2) per
# test_redos_safety); a param list longer than 120 chars simply isn't checked for re-binding.
_PARAMS_THEN_BODY = re.compile(r"\(([^)\n]{0,120})\)\s*(?:=>|\{)")
_CONTROL_HEADS = {"if", "for", "while", "switch", "with"}


def _trailing_ident(s: str) -> str:
    """The identifier at the end of `s` (after trailing whitespace), by a linear backward scan. A
    `$`-anchored regex (`[\\w$]*\\s*$`) backtracks quadratically on a hostile all-word run, so this is
    plain string work instead (test_redos_safety enforces boundedness on every module-level regex)."""
    j = len(s)
    while j > 0 and s[j - 1].isspace():
        j -= 1
    i = j
    while i > 0 and (s[i - 1].isalnum() or s[i - 1] in "_$"):
        i -= 1
    return s[i:j]


def _sink_takes_var(name: str) -> "re.Pattern[str]":
    """A sink (child_process runner / dynamic `import(` / `new Worker(`) whose LEADING argument is the
    variable `name` (already re.escape'd) used directly — see `_DECODED_ARG_TAIL`."""
    return re.compile(
        _CP_RUNNERS + r"\s*\(\s*" + name + _DECODED_ARG_TAIL
        + r"|(?<![.\w$])import\s*\(\s*" + name + _DECODED_ARG_TAIL
        + r"|\bnew\s+Worker\s*\(\s*" + name + _DECODED_ARG_TAIL)


def _name_rebound(gap: str, name: str) -> bool:
    """True if `name` (re.escape'd) is re-declared or re-introduced as a PARAMETER inside `gap` —
    meaning the sink's variable is a DIFFERENT binding than the decode's (a name collision, not a
    data flow). This catches a MODULE-LEVEL decode var colliding with a same-named param in a later
    function/method, which the brace-depth check alone cannot see (a module binding has no enclosing
    `}` to close). Recognizes EVERY param-binding form — `function f(x)`, ES6 method-shorthand /
    class method `m(x){}`, `catch(x){}`, and arrows `(x)=>` / `x=>` — by matching any `(params)`
    that is followed by `{` or `=>`, minus a leading control-flow head (`if`/`for`/… bind nothing)."""
    if re.search(r"(?:const|let|var)\s+" + name + r"\b", gap):
        return True
    name_re = re.compile(r"(?<![.\w$])" + name + r"\b")
    for m in _PARAMS_THEN_BODY.finditer(gap):
        if _trailing_ident(gap[max(0, m.start() - 40):m.start()]) in _CONTROL_HEADS:
            continue                       # `if (cond) {` etc. — a condition, binds nothing
        if name_re.search(m.group(1)):
            return True
    # single-ident arrow with no parens — `name => …` (not covered by _PARAMS_THEN_BODY)
    return re.search(r"(?<![.\w$])" + name + r"\s*=>", gap) is not None


def _decode_var_into_exec(s: str) -> bool:
    """True if a base64/hex decode assigned to a variable then flows, within a short window AND
    WITHOUT leaving the variable's scope, into a command / dynamic-module / worker sink:
    `const d = Buffer.from(p, 'base64'); execSync(d)`. This is the #1266 residual the nested
    `_DECODE_INTO_EXEC` misses (decode via a VARIABLE) and the #1212 blind spot. The sink set is
    #1266's (child_process runners / `import(` / `new Worker(`) — `eval`/`Function`/`atob` are already
    standalone `_EXEC_SINK`s so a decoded value reaching THEM is caught without this.

    THREE accuracy guards keep a short, ubiquitous var name (`p`, `data`, `config`) from FP'ing on a
    coincidental collision (FP-hunt):
      • the sink must take the decoded var DIRECTLY (bare or `.toString()`'d), never a PROPERTY of it
        (`spawn(cfg.cmd,…)` / `import(mod.entry)` mean it's a config object, not decoded bytes);
      • the name must not be RE-BOUND (re-declared / a function-or-arrow param) between decode and
        sink — that is a different binding (`_name_rebound`; catches a module-level decode colliding
        with a later same-named param);
      • the sink must sit at a brace depth the decode's block has not already closed (`_name_rebound`
        can't see a re-use with no re-declaration in a sibling block; the depth check does).
    We scrub strings/comments FIRST so their braces (and any `import(`-in-a-string) never skew the
    depth or match. Bounded window + assignment cap keep it linear. Purely static — matched in text,
    never decoded or run.

    Residuals (all the same #1185 infeasibility family — closing them needs whole-program dataflow,
    and each is covered by the CONFIRMED loader-fingerprint tier + Tier-2 density independently):
      • multi-hop reassignment — `d=Buffer.from(); c=d.toString(); exec(c)`;
      • a HOISTED binding assigned inside a nested block, run after the block closes —
        `let d; if(c){ d=Buffer.from(p,'base64'); } execSync(d);` — the block's `}` drives the depth
        negative so the scope check treats it as out-of-scope. Deliberate cost of the scope check,
        which fixes the far more realistic cross-function name-collision FP; the natural dropper keeps
        decode+exec together inside the block (caught), so this shape is contrived;
      • `sh -c <decoded>` as a NON-leading arg — `spawn('sh',['-c',d])` / `execSync('sh -c '+d)`. The
        LEADING-arg anchor is shared with #1266 and is the FP-safe choice (a decoded value in an
        args[] array is often benign); catching the shell-invocation form needs an `sh`/`-c`-aware
        arg scan — a worthwhile follow-up, not this arm's regression;
      • a deliberately-planted same-name arrow decoy between decode and exec — `const d=Buffer.from(p);
        arr.map(d=>d.id); execSync(d)` — the re-bind guard skips it; requires an exact-name shadow, so
        it is an evasion-only shape, not a natural dropper."""
    view = _scrub_comments_and_strings(s)   # code braces kept, string/comment braces removed
    for i, m in enumerate(_DECODE_TO_VAR.finditer(view)):
        if i >= _MAX_DECODE_VARS:
            break
        name = re.escape(m.group(1))
        window = view[m.end():m.end() + _INDIRECT_SINK_WINDOW]
        for sm in _sink_takes_var(name).finditer(window):
            gap = window[:sm.start()]
            # (1) Re-binding guard: if the name is re-declared or re-introduced as a function/arrow
            #     PARAMETER before the sink, the sink's variable is a different binding — a name
            #     collision, not a flow (FP-hunt: a MODULE-LEVEL `const data=Buffer.from(…)` and a
            #     later `function run(data){ spawn(data,…) }`; a module binding has no `}` to close so
            #     the brace check below can't see it).
            if _name_rebound(gap, name):
                continue
            # (2) Scope-exit guard: the decode's binding is in scope at the sink only if its block has
            #     NOT closed between them — the running brace depth never drops below 0 (an unmatched
            #     `}` that exits the binding's scope). A later `{` re-opening a sibling scope must NOT
            #     mask that exit, so we test for depth going negative at any point, not the final depth
            #     (`const p=…}` in one function then `import(p)` in the NEXT is a collision, not a flow).
            depth = 0
            closed = False
            for ch in gap:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth < 0:
                        closed = True
                        break
            if not closed:
                return True
    return False


def _scrub_comments_and_strings(s: str, scrub_strings: bool = True) -> str:
    """Scrub // and /* */ comments and ' / \" string *contents* (same length, spaces) so a
    #1208 pattern can't fire on documentation or a string that merely mentions `import(url)`.
    Template literal BODIES are kept intact (the relative-path carve-out must see `./`);
    only `${…}` expression interiors are scrubbed. Best-effort — not a full JS lexer.

    `scrub_strings=False` scrubs comments ONLY, keeping '/\" string contents verbatim. The
    data:-URI-import arm needs this: its tell (`data:…;base64,`) lives INSIDE the specifier
    string, so a full string scrub would blank the very thing it matches — but a mention in a
    // or /* */ comment must still be silenced."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            out.append("  ")
            i += 2
            while i < n and s[i] not in "\n\r":
                out.append(" ")
                i += 1
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            out.append("  ")
            i += 2
            while i + 1 < n and not (s[i] == "*" and s[i + 1] == "/"):
                out.append("\n" if s[i] == "\n" else " ")
                i += 1
            if i + 1 < n:
                out.append("  ")
                i += 2
            continue
        if c == "`":
            out.append("`")
            i += 1
            while i < n:
                ch = s[i]
                if ch == "\\" and i + 1 < n:
                    out.append(s[i:i + 2])
                    i += 2
                    continue
                if ch == "`":
                    out.append("`")
                    i += 1
                    break
                if ch == "$" and i + 1 < n and s[i + 1] == "{":
                    out.append("${")
                    i += 2
                    depth = 1
                    while i < n and depth:
                        if s[i] == "{":
                            depth += 1
                            out.append(" ")
                            i += 1
                        elif s[i] == "}":
                            depth -= 1
                            out.append("}" if depth == 0 else " ")
                            i += 1
                        else:
                            out.append(" " if s[i] != "\n" else "\n")
                            i += 1
                    continue
                out.append(ch)
                i += 1
            continue
        if c in "'\"":
            quote = c
            out.append(c)
            i += 1
            while i < n:
                ch = s[i]
                if ch == "\\" and i + 1 < n:
                    out.append(s[i:i + 2] if not scrub_strings else "  ")
                    i += 2
                    continue
                if ch == quote:
                    out.append(ch)
                    i += 1
                    break
                out.append(ch if not scrub_strings else ("\n" if ch == "\n" else " "))
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _has_corroborated_dynamic_exec(s: str, strict: bool = False) -> bool:
    """True if `s` has a #1208 residual form still missing after #1266. Folded into
    `_has_exec_sink`, whose `strict` flag splits the two callers' opposite needs (#1289):

      * ALWAYS (both callers) — the TIGHT, no-benign-analogue arms suitable for a SCAN finding: a
        `data:` executable-module `import(` (its tell lives in the specifier string, so a
        COMMENT-only scrub) and a require-receiver command runner fed a decode.
      * strict=True ONLY (the remediation "is the kept code safe to auto-clean?" gate) — the BROAD
        arms (any non-literal `import(`, any constructed child_process command). Too FP-prone to
        raise a finding, but as a conservative gate a false positive is the SAFE direction (defer to
        manual). Keeping them here — not deleting them — is why the tighten downgrades nothing."""
    # Both TIGHT arms need string CONTENTS: 2a's tell (`data:…;base64,`) and 2b's module name
    # (`'child_process'`) live inside strings, so a full string-scrub would blank them. Use a
    # comment-only scrub (strings kept) — a mention in a // or /* */ comment is still silenced.
    kept = _scrub_comments_and_strings(s, scrub_strings=False)
    if _DATA_URI_IMPORT.search(kept) or _REQUIRE_CP_DECODE.search(kept):
        return True
    # The BROAD arms (strict/remediation-gate only) match code shapes, so a full string scrub is
    # right there — a docs string mentioning `import(url)` / `execSync(cmd+x)` must not trip the gate.
    if strict:
        scrubbed = _scrub_comments_and_strings(s)
        if _DYNAMIC_IMPORT.search(scrubbed) or _CONSTRUCTED_CP.search(scrubbed):
            return True
    return False


# A self-describing inline asset (image/font/media data-URI). Stripped before the density
# and escape-run analysis so a legitimate `data:<mime>;base64,` blob does not inflate a
# line's length/entropy. (base64 blobs are no longer a standalone signal — see #1212.)
_DATA_URI = re.compile(r"data:[\w.+-]+/[\w.+-]+;base64,[A-Za-z0-9+/]+={0,2}", re.IGNORECASE)

# ── Wrap/concat-resistant escape-payload-at-rest detection (#1053 Tier-2 hardening) ──
# A payload encoded as a dense run of \xNN/\uNNNN escapes decoded at runtime (Buffer.from /
# fromCodePoint) can dodge the escape-run detector by splitting into short quoted chunks
# joined by `+`/`,` (`"\\x41\\x42" + "\\x43…"`), whose quote/sep/space seams break the run.
# _dechunk normalizes those seams away so the escape-run test sees the reassembled content.
# (base64 reassembly is no longer tested — a base64 blob is benign data regardless of
# splitting, #1212 — so _dechunk now serves ONLY the escape-run arm.)

# A JS string-reassembly seam: a closing quote, a `+` (concat) OR `,` (array element)
# separator, an opening quote — any whitespace/newlines between. Collapsing it rejoins
# `"\\x41" + "\\x42"` AND `["\\x41","\\x42"].join("")` into one run. Only quote-SEP-quote
# seams match, so a `+` inside a chunk, arithmetic `a + b`, a `["x", host]` array with a
# variable, and a list separator in prose are all untouched. The downstream escape-run gate
# (48+ run AND decoded byte-range AND entropy) is what keeps this FP-safe: reassembling a
# legit string array that carries no dense escape run trips nothing.
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

    # Tier 1 — self-evident constructs over the RAW content (never splitlines, so a
    # wrapped charcode array / base64 blob spanning line breaks is still seen).
    flat = body.replace("\n", "").replace("\r", "")
    if _NUM_ARRAY.search(flat):
        return ObfuscationVerdict(True, "charcode/byte numeric-array literal (string shuffler)")
    # Search the raw body AND the newline-flattened form so an exec sink wrapped
    # across line breaks (`sfL['constructor']\n(decoded)`) is still seen.
    if _has_exec_sink(body) or _has_exec_sink(flat):
        return ObfuscationVerdict(True, "dynamic-exec sink (eval/Function/atob/fromCharCode/constructor)")
    # Decode→exec dropper (#1266): a base64/hex decode fed straight into a command/module sink
    # (child_process / import() / Worker) — the FLOW, not the encoded bytes. Static match only.
    if _DECODE_INTO_EXEC.search(body) or _DECODE_INTO_EXEC.search(flat):
        return ObfuscationVerdict(True, "base64/hex decoded and run via a command/module sink (child_process/import/Worker)")
    # A base64 blob — whether CONTIGUOUS or reassembled from concat/array chunks — is NOT a
    # verdict on its own (#1212). base64 is ubiquitous benign DATA: JWTs, API tokens, SRI
    # hashes, cert-pin / JWKS key arrays, crypto KAT vectors, inlined assets. It has near-
    # zero precision as an obfuscation signal (a real scan flagged three clean *.test.tsx
    # files that merely held a mock JWT), and the `,`/`+` seams of an ordinary base64 ARRAY
    # are indistinguishable from a split-payload reassembly without runtime data flow. A real
    # packed loader is still caught by its EXEC step — the exec-sink / decode→exec / charcode-
    # array / escape-run arms, or the CONFIRMED loader-fingerprint tier that scans this file
    # independently — not by the mere presence of encoded bytes at rest.
    #
    # BUT a hardcoded blob decoded through a VARIABLE and then RUN is the dropper the nested
    # #1266 check misses (`const d = Buffer.from(p,'base64'); execSync(d)`). Flag ONLY that
    # conjunction — an encoded blob present AND a decode→variable→command/module/worker flow —
    # so a lone blob (the #1212 FP class) stays clean while the in-file dropper is caught.
    # _dechunk first so a split/concat-reassembled blob still corroborates.
    deassetted = _DATA_URI.sub("", flat)
    if _has_encoded_payload(_dechunk(deassetted)) and _decode_var_into_exec(body):
        return ObfuscationVerdict(True, "base64 payload decoded via a variable and run (command/module/worker sink)")
    # The dense escape-encoded byte run stays: unlike base64, a 48+ `\xNN`/`\uNNNN` run gated
    # on byte-range + entropy has no benign-data analogue (nobody writes a token/asset that
    # way), so it is FP-safe. _dechunk first so a chunked escape payload is reassembled.
    if _escape_run(_dechunk(deassetted)):
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
    if _DECODE_INTO_EXEC.search(text):
        return ObfuscationVerdict(True, "base64/hex decoded and run via a command/module sink (child_process/import/Worker)")
    # A base64 blob is NOT a delta verdict on its own (#1212): a merge/feature commit that
    # introduces a base64 token, a cert-pin / JWKS key array, or a KAT-vector table is data,
    # not an evil-merge tell. But a blob decoded through a VARIABLE and then RUN inside the hunk
    # (`const p='<blob>'; const d=Buffer.from(p,'base64'); execSync(d)`) is the evil-merge dropper
    # #1266's nested check misses — flag only that conjunction (blob present AND decode→var→sink).
    de_intro = _DATA_URI.sub("", text)
    if _has_encoded_payload(_dechunk(de_intro)) and _decode_var_into_exec(text):
        return ObfuscationVerdict(True, "base64 payload decoded via a variable and run (command/module/worker sink)")
    # A genuinely merge-introduced payload is otherwise caught by its exec sink (above), the
    # nested decode→exec flow, its charcode array, or the loader-fingerprint corroboration.

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
