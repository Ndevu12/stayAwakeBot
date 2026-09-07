#!/usr/bin/env python3
"""Detection of constructs that turn data back into running code.

`_has_exec_sink(text)` answers whether a chunk of source contains a dynamic-execution sink. Used by
the obfuscation entry points and by the remediation gate, which passes `strict=True` to require the
stronger forms. Depends on `taint`; `taint` never depends on this module.
"""
from __future__ import annotations

import re
import unicodedata

from stayawake.bots.security.taint.flow import _has_corroborated_dynamic_exec
from stayawake.bots.security.taint.model import (
    CP_RUNNERS, CP_MODULES, COMMAND_RUNNING_MODULES)


_NUM_ARRAY = re.compile(r"\[\s*(?:0x[0-9a-fA-F]+|\d{1,3})\s*(?:,\s*(?:0x[0-9a-fA-F]+|\d{1,3})\s*){7,}\]")
_EXEC_SINK = re.compile(
    r"(?<![\w$])eval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*[\"']|\batob\s*\(|"
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
_UNCURRY_THIS = r"\s*\.\s*(?:prototype\s*\.\s*)?(?:call|apply|bind)\s*\.\s*bind\b"
_GLOBAL_OBJECT = r"(?:globalThis)"
_THE_BUILTIN = (
    rf"(?:(?:{_GLOBAL_OBJECT}\s*\.\s*)?(?:eval|Function)\b(?!{_UNCURRY_THIS})"
    rf"|{_GLOBAL_OBJECT}\s*\[\s*[\"'](?:eval|Function)[\"']\s*\])"
)
_NAME = r"[A-Za-z_$][\w$]{0,64}"
_BIND_EVAL_FN = re.compile(
    rf"(?:const|let|var)\s+({_NAME})\s*=\s*{_THE_BUILTIN}"
    rf"|(?:const|let|var)\s*\{{[^{{}}\n]{{0,120}}?(?<![\w$])(?:eval|Function)\s*:\s*({_NAME})"
    rf"[^{{}}\n]{{0,120}}?\}}\s*=\s*{_GLOBAL_OBJECT}\b(?!\s*[.\[])"
)
_BIND_DANGEROUS_KEY = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[\"'](?:eval|Function|constructor)[\"']"
)
_ALIAS_CALL_WINDOW = 240
_BARE_BINDING_END = re.compile(r"[ \t]*(?:;|$|\r?\n(?!\s*[.\[]))")
_FAR_ALIAS_MIN_NAME = 3
_NOT_A_DECLARATION = r"(?<![\w$.#])(?<!function\s)"
_NOT_A_METHOD_BODY = r"(?![^()\n]{0,200}\)\s*\{)"
_SINK_NAME = re.compile(
    r"eval|Function|atob|runInThisContext|runInNewContext|vm|require|Reflect|"
    + "|".join(sorted(CP_RUNNERS | CP_MODULES, key=len, reverse=True)),
    re.IGNORECASE,
)
_NAME_MARKS = frozenset({"Mn", "Mc", "Pc"})


def _continues_a_name(ch: str) -> bool:
    """Return True if `ch` can be part of a JavaScript identifier."""
    return ch.isalnum() or ch in "_$" or unicodedata.category(ch) in _NAME_MARKS


def _sink_calls(pattern: re.Pattern, view: str):
    """Yield the matches of `pattern` in `view` whose sink name is a whole identifier."""
    for m in pattern.finditer(view):
        name = _SINK_NAME.search(m.group(0))
        if name is None:
            yield m
            continue
        start, end = m.start() + name.start(), m.start() + name.end()
        if start and _continues_a_name(view[start - 1]):
            continue
        if end < len(view) and _continues_a_name(view[end]):
            continue
        yield m


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
        alias = next(g for g in m.groups() if g)
        name = re.escape(alias)
        far = (m.group(1) and len(alias) >= _FAR_ALIAS_MIN_NAME
               and _BARE_BINDING_END.match(s, m.end()))
        if re.search(rf"(?<![\w$]){name}\s*\(", s[m.end():m.end() + _ALIAS_CALL_WINDOW]):
            return True
        if far and re.search(rf"{_NOT_A_DECLARATION}{name}\s*\({_NOT_A_METHOD_BODY}", s[m.end():]):
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
    if (any(_sink_calls(_EXEC_SINK, view)) or _REFLECTIVE_EXEC.search(view)
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

_REGEXP_RECEIVER = re.compile(
    r"(?:/[^/\n]{1,200}/[gimsuyd]{0,7}|\bRegExp\s*\([^)\n]{0,200}\))\s*\.\s*$")
_BARE_EXEC_CALL = re.compile(r"^exec\s*\($")

_IDENT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")


def _named_receiver(before: str) -> str | None:
    """The identifier in `<name> .` at the very end of `before`, or None.

    Read backwards rather than matched: the equivalent pattern is quadratic on a long identifier
    run, which the ReDoS guard rejects.
    """
    i = len(before) - 1
    while i >= 0 and before[i].isspace():
        i -= 1
    if i < 0 or before[i] != ".":
        return None
    i -= 1
    while i >= 0 and before[i].isspace():
        i -= 1
    end = i + 1
    while i >= 0 and before[i] in _IDENT_CHARS:
        i -= 1
    name = before[i + 1:end]
    return name if name and not name[0].isdigit() else None


_ASSIGNED_A_REGEXP = re.compile(r"(?:/(?![/*])|new\s{1,8}RegExp\b|RegExp\s{0,8}\()")
_LOADS_A_MODULE = re.compile(r"(?:await\s{1,8})?(?:require|import)\s{0,8}\(\s{0,8}")
_LITERAL_SPECIFIER = re.compile(r"(['\"])([^'\"\n]{0,200})\1\s{0,8}\)")
NO_MODULE, CP_MODULE, OTHER_MODULE, UNNAMED_MODULE = "", "cp", "other", "?"
_RUNNER_PROVENANCE = frozenset({CP_MODULE, UNNAMED_MODULE})


def _module_loaded(value: str) -> str:
    """Which module a value loads.

    Takes the text of an assigned value. Returns `CP_MODULE` when the specifier names a module
    that runs commands, `OTHER_MODULE` when it names any other, `UNNAMED_MODULE` when the
    specifier is not a plain literal, and `NO_MODULE` when nothing is loaded.
    """
    m = _LOADS_A_MODULE.search(value)
    if m is None:
        return NO_MODULE
    named = _LITERAL_SPECIFIER.match(value, m.end())
    if named is None:
        return UNNAMED_MODULE
    return CP_MODULE if named.group(2) in COMMAND_RUNNING_MODULES else OTHER_MODULE


_NOT_AN_ASSIGNMENT = frozenset("=!<>+-*/%&|^")
_LAZY_ASSIGNMENT = frozenset("|&?")


_STATEMENT_WINDOW = 200


def _statement_at(view: str, start: int) -> str:
    """The rest of one statement.

    Takes `view` and the offset to read from. Returns at most `_STATEMENT_WINDOW` characters, cut
    at the first `;` or line break that no bracket is open at.
    """
    window = view[start:start + _STATEMENT_WINDOW]
    depth = 0
    for i, ch in enumerate(window):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch in ";\n" and depth <= 0:
            return window[:i]
    return window


def _decodes_its_argument(view: str, start: int) -> bool:
    """Whether a call decodes inside its own argument list.

    Takes `view` and `start`, the offset just past the opening parenthesis. Returns True when a
    decode primitive appears before the statement ends.
    """
    return bool(_DECODE_PRIMITIVE.search(_statement_at(view, start)))


def _assignments(view: str) -> tuple[dict[str, list[tuple[int, int]]],
                                     dict[str, list[tuple[int, int]]]]:
    """Every `name = value` in `view`, and every `owner.name = value`.

    Takes the comment-stripped file text. Returns two tables, name -> [(offset of the `=`, offset
    of the value)] in the order they appear: what each name was given, and what was written onto
    each object.
    """
    out: dict[str, list[tuple[int, int]]] = {}
    owners: dict[str, list[tuple[int, int]]] = {}
    i = view.find("=")
    while i != -1:
        nxt, prev = view[i + 1:i + 2], view[i - 1:i]
        lazy = prev in _LAZY_ASSIGNMENT and view[i - 2:i - 1] == prev
        if nxt != "=" and (lazy or prev not in _NOT_AN_ASSIGNMENT):
            j = i - 3 if lazy else i - 1
            while j >= 0 and view[j].isspace():
                j -= 1
            end = j + 1
            while j >= 0 and view[j] in _IDENT_CHARS:
                j -= 1
            name = view[j + 1:end]
            if name and not name[0].isdigit():
                v = i + 1
                while v < len(view) and view[v].isspace():
                    v += 1
                out.setdefault(name, []).append((i, v))
                if j >= 0 and view[j] == ".":
                    k = j - 1
                    while k >= 0 and view[k] in _IDENT_CHARS:
                        k -= 1
                    owner = view[k + 1:j]
                    if owner and not owner[0].isdigit():
                        owners.setdefault(owner, []).append((i, v))
        i = view.find("=", i + 1)
    return out, owners


def _last_value(view: str, assignments: dict[str, list[tuple[int, int]]], name: str,
                before: int) -> str | None:
    """The value the last assignment to `name` before offset `before` gives it.

    Takes the comment-stripped file text, the assignment table, the receiver name and the call's
    offset. Returns one statement of text, or None when the name is never assigned earlier.
    """
    latest = None
    for pos, value in assignments.get(name, ()):
        if pos >= before:
            break
        latest = value
    return None if latest is None else _statement_at(view, latest)


def _properties(view: str) -> dict[str, list[tuple[int, int]]]:
    """Every `name: value` in `view` whose value loads a command-running module.

    Takes the comment-stripped file text. Returns name -> [(offset of the `:`, offset of the
    value)], so a receiver taken from an object literal can be answered.
    """
    out: dict[str, list[tuple[int, int]]] = {}
    i = view.find(":")
    while i != -1:
        v = i + 1
        while v < len(view) and view[v].isspace():
            v += 1
        if _module_loaded(_statement_at(view, v)) in _RUNNER_PROVENANCE:
            j = i - 1
            while j >= 0 and view[j].isspace():
                j -= 1
            end = j + 1
            while j >= 0 and view[j] in _IDENT_CHARS:
                j -= 1
            name = view[j + 1:end]
            if name and not name[0].isdigit():
                out.setdefault(name, []).append((i, v))
        i = view.find(":", i + 1)
    return out


_BARE_ALIAS = re.compile(r"^(?:[A-Za-z_$][\w$]{0,64}\s{0,8}\.\s{0,8}){0,8}([A-Za-z_$][\w$]{0,64})\s{0,8}(?:,|$)")
_ALIAS_NAMES = 64


def _ever_loads_a_runner_module(view: str, tables, name: str) -> bool:
    """Whether any binding of `name` anywhere in `view` loads a command-running module.

    Takes the comment-stripped file text, the tables of bindings and the receiver name. Returns
    True when one of them, or one of the names they alias, names such a module or hides the name
    it loads. At most `_ALIAS_NAMES` names are followed, each one once.
    """
    seen, pending = {name}, [name]
    while pending:
        current = pending.pop()
        for table in tables:
            for _, value in table.get(current, ()):
                statement = _statement_at(view, value).strip()
                if _module_loaded(statement) in _RUNNER_PROVENANCE:
                    return True
                alias = _BARE_ALIAS.match(statement)
                if (alias is not None and alias.group(1) not in seen
                        and len(seen) < _ALIAS_NAMES):
                    seen.add(alias.group(1))
                    pending.append(alias.group(1))
    return False


_RECEIVER_LOOKBACK = 224


def _runs_a_command(view: str) -> bool:
    """Whether a child_process runner is called.

    Takes `view`, the file text with comments removed. Returns True at the first call that counts.
    """
    assignments: dict[str, list[tuple[int, int]]] | None = None
    tables: tuple[dict[str, list[tuple[int, int]]], ...] = ()
    for m in _sink_calls(_COMMAND_RUNNER, view):
        if _BARE_EXEC_CALL.match(m.group(0)):
            before = view[max(0, m.start() - _RECEIVER_LOOKBACK):m.start()]
            if _REGEXP_RECEIVER.search(before):
                continue
            named = _named_receiver(before)
            if named is not None:
                if assignments is None:
                    assignments, owners = _assignments(view)
                    tables = (assignments, owners, _properties(view))
                bound = _last_value(view, assignments, named, m.start())
                if bound is not None and _ASSIGNED_A_REGEXP.match(bound):
                    continue
                if not (_ever_loads_a_runner_module(view, tables, named)
                        or _decodes_its_argument(view, m.end())):
                    continue
        return True
    return False


_CHARCODE_CONSUMER = re.compile(r"fromCharCode|fromCodePoint", re.IGNORECASE)


def _has_exec_sink_beyond_decoding(s: str) -> bool:
    """True when something in `s` actually RUNS, rather than merely decodes.

    A decode primitive on its own is not that: `atob` returning into `JSON.parse` is every JWT reader
    in the ecosystem. It counts only when the file also holds a command runner, which is the flow the
    taint model describes — decode alone is data, sink alone is ordinary code, the pair is the tell.

    The text is NOT edited to ask this. Blanking the decode call first also blinds the decode-to-exec
    flow detector, which needs both halves; that broke two real detections."""
    view = _fold_string_concats(s)
    if (any(_sink_calls(_EXEC_SINK_NO_DECODE, view)) or _REFLECTIVE_EXEC.search(view)
            or _has_corroborated_dynamic_exec(view) or _has_obfuscated_exec_forms(view)):
        return True
    if any(not _NEW_CLONE_PREFIX.search(view[max(0, m.start() - 48):m.start()])
           for m in _CONSTRUCTOR_EXEC.finditer(view)):
        return True
    return bool(any(_sink_calls(_DECODE_PRIMITIVE, view)) and _runs_a_command(view))


def _is_charcode_shuffler(s: str) -> bool:
    """A numeric-array literal that is consumed as character codes."""
    return bool(_NUM_ARRAY.search(s) and _CHARCODE_CONSUMER.search(s))
