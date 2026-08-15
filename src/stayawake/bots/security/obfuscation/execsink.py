#!/usr/bin/env python3
"""Dynamic-execution SINK detection — the self-evident "this turns data back into code" constructs.

Single responsibility: decide whether a chunk of source contains a dynamic-exec sink — the classic
eval/Function/atob/fromCharCode/vm-runner/reflective-constructor forms (#1053/#1206), the #1207
obfuscated forms (split-token concat-fold, indirect comma-call, light alias / runtime key), and (via
`taint.flow`) the #1208 corroborated-dynamic-exec residual. `_has_exec_sink` is the whole-file /
delta entry points' Tier-1 check and the remediation gate (`strict=True`). The decode→exec FLOW
primitives live in `taint/`; this module borrows only `_has_corroborated_dynamic_exec` from there —
the dependency flows `obfuscation → taint`, never the reverse.
"""
from __future__ import annotations

import re

from stayawake.bots.security.taint.flow import _has_corroborated_dynamic_exec
from stayawake.bots.security.taint.model import CP_RUNNERS, CP_MODULES


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


# `atob` and `String.fromCharCode` DECODE; they do not run anything. Grouping them with the exec
# sinks makes every JWT reader, data-URI handler and base64 utility a finding — measured on a
# 19-line JWT decoder whose `atob` result reaches `JSON.parse` and is returned.
#
# They stay in `_EXEC_SINK` because the REMEDIATION gate (`strict=True`) must keep deferring on them:
# there, trusting a benign shape can pass an RCE, so a decode primitive in kept code is a reason to
# stop. Only the FINDING path asks the question below, where the cost of over-firing is the operator
# learning to dismiss the class.
_DECODE_PRIMITIVE = re.compile(r"\batob\s*\(|String\s*[.\[]\s*[\"']?fromCharCode", re.IGNORECASE)
_EXEC_SINK_NO_DECODE = re.compile(
    "|".join(a for a in _EXEC_SINK.pattern.split("|")
             if "atob" not in a and "fromCharCode" not in a),
    re.IGNORECASE,
)

# What makes a numeric array a string shuffler is being CONSUMED as character codes. The literal
# alone is every size table, colour table and lookup table in existence — measured on
# `[72, 96, 128, 144, 152, 180, 192, 384, 512]`, a list of PWA icon pixel sizes.
# The command runners named by the taint model (`CP_RUNNERS`), which corroborate a decode primitive.
_COMMAND_RUNNER = re.compile(
    r"\b(?:" + "|".join(sorted(CP_RUNNERS)) + r")\s*\(|\b(?:" + "|".join(sorted(CP_MODULES)) + r")\b")

_CHARCODE_CONSUMER = re.compile(r"fromCharCode|fromCodePoint", re.IGNORECASE)


def _has_exec_sink_beyond_decoding(s: str) -> bool:
    """True when something in `s` actually RUNS, rather than merely decodes.

    A decode primitive on its own is not that: `atob` returning into `JSON.parse` is every JWT reader
    in the ecosystem. It counts only when the file also holds a command runner, which is the flow the
    taint model describes — decode alone is data, sink alone is ordinary code, the pair is the tell.

    The text is NOT edited to ask this. Blanking the decode call first also blinds the decode-to-exec
    flow detector, which needs both halves; that broke two real detections."""
    view = _fold_string_concats(s)
    if (_EXEC_SINK_NO_DECODE.search(view) or _REFLECTIVE_EXEC.search(view)
            or _has_corroborated_dynamic_exec(view) or _has_obfuscated_exec_forms(view)):
        return True
    if any(not _NEW_CLONE_PREFIX.search(view[max(0, m.start() - 48):m.start()])
           for m in _CONSTRUCTOR_EXEC.finditer(view)):
        return True
    return bool(_DECODE_PRIMITIVE.search(view) and _COMMAND_RUNNER.search(view))


def _is_charcode_shuffler(s: str) -> bool:
    """A numeric-array literal that is consumed as character codes."""
    return bool(_NUM_ARRAY.search(s) and _CHARCODE_CONSUMER.search(s))
