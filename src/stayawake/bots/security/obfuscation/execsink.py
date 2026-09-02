#!/usr/bin/env python3
"""Detection of constructs that turn data back into running code.

`_has_exec_sink(text)` answers whether a chunk of source contains a dynamic-execution sink. Used by
the obfuscation entry points and by the remediation gate, which passes `strict=True` to require the
stronger forms. Depends on `taint`; `taint` never depends on this module.
"""
from __future__ import annotations

import re

from stayawake.bots.security.taint.flow import _has_corroborated_dynamic_exec
from stayawake.bots.security.taint.model import CP_RUNNERS, CP_MODULES


_NUM_ARRAY = re.compile(r"\[\s*(?:0x[0-9a-fA-F]+|\d{1,3})\s*(?:,\s*(?:0x[0-9a-fA-F]+|\d{1,3})\s*){7,}\]")
_EXEC_SINK = re.compile(
    r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*[\"']|\batob\s*\(|"
    r"String\s*[.\[]\s*[\"']?fromCharCode|global\s*\[\s*['\"]!['\"]\s*\]\s*=|"
    r"\brunInThisContext\s*\(|\brunInNewContext\s*\(|"
    r"\bvm\s*\.\s*runInContext\s*\(|"
    r"\brequire\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*[\"']vm[\"']\s*\)\s*(?:\?\s*)?\.\s*runInContext\s*\(|"
    r"\bReflect\s*\.\s*(?:apply|construct)\s*\(\s*(?:eval|Function)\b",
    re.IGNORECASE,
)
_CTOR_ACCESS = r"(?:\.\s*constructor\b|\[\s*[\"']constructor[\"']\s*\])"
_REFLECTIVE_EXEC = re.compile(
    r"\[\s*[\"'](?:eval|Function)[\"']\s*\]\s*\("
    r"|" + _CTOR_ACCESS + r"\s*" + _CTOR_ACCESS + r"\s*\("
    r"|(?<![.\w$])set(?:Timeout|Interval)\s*\(\s*[\"'\x60]")
_CONSTRUCTOR_EXEC = re.compile(r"\[\s*[\"']constructor[\"']\s*\]\s*\(")
_NEW_CLONE_PREFIX = re.compile(r"\bnew\s+[\w$.)\]]*\s*$")

# ── Obfuscated exec sinks ─────────────────────────────────────────────────────
_STR_CONCAT_FOLD = re.compile(
    r"(['\"])([^'\"\\\n]{0,64})\1\s*\+\s*\1([^'\"\\\n]{0,64})\1"
)
_INDIRECT_EVAL = re.compile(
    r"\(\s*(?:0|1|void\s+0|null|undefined|!0|!1)\s*,\s*(?:eval|Function)\s*\)\s*\("
)
_GLOBAL_OBJECT = r"(?:globalThis|window|global|self)"
# Bounded on both axes: an unbounded segment inside a repeated group backtracks catastrophically on
# a long run of identifier characters, which test_redos_safety measured at >5s on 300,000 of them.
_NAME = r"[A-Za-z_$][\w$]{0,64}"
_PROPERTY_PATH = rf"(?:{_NAME}\s*\.\s*){{1,6}}{_NAME}"
# `Function.prototype.call.bind(x)` borrows a method from a FOREIGN object and is the uncurry-this
# idiom. `Function.prototype.constructor`, `eval.bind(g)` and `eval.constructor` are the builtin
# itself, and they run — so the exclusion names that idiom rather than every member access on it.
_UNCURRY_THIS = r"\s*\.\s*prototype\s*\.\s*(?:call|apply|bind)\s*\.\s*bind\b"
_BUILTIN_NAME = rf"(?:eval|Function)(?![\w$])(?!{_UNCURRY_THIS})"
_THE_BUILTIN_ITSELF = (
    rf"(?:{_BUILTIN_NAME}"
    rf"|{_GLOBAL_OBJECT}\s*\.\s*{_BUILTIN_NAME}"
    rf"|{_GLOBAL_OBJECT}\s*\[\s*[\"'](?:eval|Function)[\"']\s*\])"
)
_BIND_EVAL_FN = re.compile(
    rf"(?:const|let|var)\s+({_NAME})\s*=\s*{_THE_BUILTIN_ITSELF}"
    rf"|({_PROPERTY_PATH})\s*=(?!=)\s*{_THE_BUILTIN_ITSELF}"
    # No declarator: a class field (`$eval = eval`) and a plain reassignment bind just as well.
    rf"|(?<![.\w$])({_NAME})\s*=(?!=)\s*{_THE_BUILTIN_ITSELF}"
    # `{ eval: X }` renames it out; `{ X: eval }` names it in. Both bind, in opposite directions.
    rf"|(?:const|let|var)\s*\{{[^}}\n]{{0,120}}?(?<![\w$])(?:eval|Function)\s*:\s*({_NAME})"
    rf"|({_NAME})\s*:\s*{_THE_BUILTIN_ITSELF}"
)
_BIND_DANGEROUS_KEY = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[\"'](?:eval|Function|constructor)[\"']"
)
_ALIAS_CALL_WINDOW = 240


def _fold_string_concats(s: str, max_passes: int = 24) -> str:
    """Collapse adjacent same-quote string concatenations (`'ev'+'al'` → `'eval'`) so the
    existing sink regexes see the reassembled token. Bounded chunk length (64) and
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
    exec form from. Call-required and `new`-clone-carved; Babel `(0, _mod.x)(` stays
    clean."""
    if _INDIRECT_EVAL.search(s):
        return True
    for m in _BIND_EVAL_FN.finditer(s):
        bound = next((g for g in m.groups() if g), None)
        if not bound:
            continue
        called = r"\s*\.\s*".join(re.escape(part.strip()) for part in bound.split("."))
        # The whole text, not a window: the binding IS the signal here, and a hoisted function may
        # call it from above. A 240-char window missed a real alias by 600 characters.
        if re.search(rf"(?<![\w$]){called}\s*\(", s):
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
    double-constructor Function reach), a residual form (see `_has_corroborated_dynamic_exec`),
    a obfuscated form (split-token via concat-fold, indirect comma-call, light alias /
    runtime-key), or a SINGLE reflective bracket-constructor call that is NOT a `new`-prefixed
    polymorphic clone (the benign idiom the worm never uses). Every single-constructor occurrence is
    checked, so a `new`-clone earlier can't mask a real sink later.

    `strict=True` is the REMEDIATION gate mode (deciding a surgically-excised file is benign enough
    to auto-clean), and makes the whole check MORE conservative in two ways: (1) it DROPS the
    `new`-clone carve-out — every single bracket-constructor call counts; and (2) it enables the
    BROAD arms (any non-literal import / constructed child_process command) that are too
    FP-prone for a scan finding but safe as a gate. In both, deferring on a benign shape is a
    safe false-positive, whereas trusting it could pass an RCE hidden in kept code."""
    view = _fold_string_concats(s)
    if (_EXEC_SINK.search(view) or _REFLECTIVE_EXEC.search(view)
            or _has_corroborated_dynamic_exec(view, strict=strict) or _has_obfuscated_exec_forms(view)):
        return True
    return any(
        strict or not _NEW_CLONE_PREFIX.search(view[max(0, m.start() - 48):m.start()])
        for m in _CONSTRUCTOR_EXEC.finditer(view)
    )


_DECODE_PRIMITIVE = re.compile(r"\batob\s*\(|String\s*[.\[]\s*[\"']?fromCharCode", re.IGNORECASE)
_EXEC_SINK_NO_DECODE = re.compile(
    "|".join(a for a in _EXEC_SINK.pattern.split("|")
             if "atob" not in a and "fromCharCode" not in a),
    re.IGNORECASE,
)

_COMMAND_RUNNER = re.compile(
    r"\b(?:" + "|".join(sorted(CP_RUNNERS)) + r")\s*\(|\b(?:" + "|".join(sorted(CP_MODULES)) + r")\b")

# What a token reader has before `.exec(`. Excluding every DOTTED receiver instead also excluded
# `cp.exec(atob(p))`, and a dropper that conceals the module name behind a decode leaves no literal
# for the module arm to catch — so the more obfuscated it was, the better it evaded.
_REGEXP_RECEIVER = re.compile(
    r"(?:/[^/\n]{1,200}/[gimsuyd]{0,7}|\bRegExp\s*\([^)\n]{0,200}\))\s*\.\s*$")


def _runs_a_command(view: str) -> bool:
    """True when `view` holds a command runner that is not `RegExp.prototype.exec`."""
    for m in _COMMAND_RUNNER.finditer(view):
        if m.group(0).lstrip().startswith("exec") and _REGEXP_RECEIVER.search(view[:m.start()]):
            continue
        return True
    return False

_CHARCODE_CONSUMER = re.compile(r"fromCharCode|fromCodePoint", re.IGNORECASE)


_FRAMEWORK_MEMBER_EVAL = re.compile(rf"(?<![\w$]){_NAME}\s*\.\s*\$\$?eval\s*\($")


def _sink_beyond_decoding(view: str, framework_members_excused: bool):
    """The first `_EXEC_SINK_NO_DECODE` match that counts, or None.

    With `framework_members_excused`, an `eval` reached through a `$`-prefixed member of a NAMED
    receiver does not count: `page.$eval` and `scope.$eval` are framework methods. The receiver has
    to be an identifier — `...` also ends in a dot, and `[...$eval(x)]` is a bare binding that runs.
    A real rebinding is caught at its assignment by `_has_obfuscated_exec_forms`, which is what makes
    excusing the call site safe at all."""
    for m in _EXEC_SINK_NO_DECODE.finditer(view):
        if framework_members_excused and _FRAMEWORK_MEMBER_EVAL.search(view[:m.end()]):
            continue
        return m
    return None


def _has_exec_sink_beyond_decoding(s: str, framework_members_excused: bool = False) -> bool:
    """True when something in `s` actually RUNS, rather than merely decodes.

    A decode primitive on its own is not that: `atob` returning into `JSON.parse` is every JWT reader
    in the ecosystem. It counts only when the file also holds a command runner, which is the flow the
    taint model describes — decode alone is data, sink alone is ordinary code, the pair is the tell.

    The text is NOT edited to ask this. Blanking the decode call first also blinds the decode-to-exec
    flow detector, which needs both halves; that broke two real detections.

    `framework_members_excused` is the SCAN's opt-in, and it defaults off so the two consumers that
    must never take it — the corroborator for a confirmed code-loader signature, and remediation
    through `analyze_file` — keep the full arm without naming it. Off, this is byte-identical."""
    view = _fold_string_concats(s)
    if (_sink_beyond_decoding(view, framework_members_excused) or _REFLECTIVE_EXEC.search(view)
            or _has_corroborated_dynamic_exec(view) or _has_obfuscated_exec_forms(view)):
        return True
    if any(not _NEW_CLONE_PREFIX.search(view[max(0, m.start() - 48):m.start()])
           for m in _CONSTRUCTOR_EXEC.finditer(view)):
        return True
    return bool(_DECODE_PRIMITIVE.search(view) and _runs_a_command(view))


def _is_charcode_shuffler(s: str) -> bool:
    """A numeric-array literal that is consumed as character codes."""
    return bool(_NUM_ARRAY.search(s) and _CHARCODE_CONSUMER.search(s))
