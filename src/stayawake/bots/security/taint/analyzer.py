#!/usr/bin/env python3
"""The decode→exec dropper analyzer — the ONE functionality that traces the model's flow.

Given a chunk of hand-authored source, decide whether a baked encoded payload is DECODED and then
EXECUTED (see `model` for the precise threat this detects and, just as importantly, what it does not).
This is the single entry point `obfuscation.analyze_file` / `analyze_delta` call for that flow; it
consolidates the decode→exec arms into one place and closes the shell code-argument gap the
leading-argument arms miss (`spawn('sh',['-c',<decoded>])`, `execSync('sh -c '+<decoded>)`).

Design: reuse the already-adversarially-hardened leading-argument detection verbatim (no regression),
and add the shell code-position forms with the SAME discipline — a nested decode is self-evident, a
decode-through-a-variable is corroborated by a baked blob and scope-guarded (a decoded value reaching
a shell `-c` slot has no benign analogue, but a bare variable in an args[] array does, so the shell
interpreter + code-flag structure is what makes it a sink, per the model). Purely static: the recipe
is matched in text, never decoded or run. Heuristic → SUSPICIOUS.
"""
from __future__ import annotations

import re

from stayawake.bots.security import obfuscation as _obf
from stayawake.bots.security.taint import model

# Reason strings (redaction-safe evidence).
_R_DIRECT = "base64/hex decoded and run via a command/module sink (child_process/import/Worker)"
_R_VAR = "base64 payload decoded via a variable and run (command/module/worker sink)"
_R_SHELL = "base64/hex decoded and run as a shell command (sh/bash/cmd/powershell -c)"

# ── Shell code-position building blocks (from the model, longest-first so `cmd.exe` beats `cmd`) ──
_SHELL_BASE = "(?:" + "|".join(
    re.escape(s) for s in sorted(model.SHELL_INTERPRETERS, key=len, reverse=True)) + ")"
# Path-aware: an optional bounded directory prefix so `/opt/homebrew/bin/bash` / `C:\…\cmd.exe` match
# by BASENAME (the model's stated intent). Bounded {0,80} + `[^'\"\x60\s]` keep it linear (the
# interpreter must end the program token, forced by the surrounding quote / whitespace-flag).
_SHELL_ALT = r"(?:[^'\"\x60\s]{0,80}[/\\])?" + _SHELL_BASE
_FLAG_ALT = "(?:" + "|".join(
    re.escape(f) for f in sorted(model.SHELL_CODE_FLAGS, key=len, reverse=True)) + ")"
_CP_ALT = "(?:" + "|".join(sorted(model.CP_RUNNERS, key=len, reverse=True)) + ")"

# argv form: `<cp>('<shell>', [ … '<flag>', <PAYLOAD> … ])`. The `('sh', ['-c', …])` shape never
# occurs for RegExp.exec / an EventEmitter, so the bare runner names are safe HERE (unlike a leading
# string arg). `[^\]\n]{0,120}?` bounds the pre-flag argv scan (ReDoS-safe) AND skips an `env`-style
# leading interpreter token (`('env', ['bash','-c',…])`).
_ARGV_HEAD = (
    r"(?<![.\w$])" + _CP_ALT + r"\s*\(\s*['\"]" + _SHELL_ALT + r"['\"]\s*,\s*\[[^\]\n]{0,120}?"
    r"['\"]" + _FLAG_ALT + r"['\"]\s*,\s*")
# array form: `['<shell>', … '<flag>', <PAYLOAD> …]` — an array literal `.join`ed into a command
# (`['sh','-c',d].join(' ')`) or spread; the shell sits INSIDE the array (distinct from _ARGV_HEAD).
_INARRAY_HEAD = (
    r"\[\s*['\"]" + _SHELL_ALT + r"['\"]\s*,\s*[^\]\n]{0,80}?['\"]" + _FLAG_ALT + r"['\"]\s*,\s*")
# inline form: `<cp>('<shell> [<interp>] <flag> …' + …)` / `` `…${…}` `` — a leading command STRING
# beginning with a shell + code-flag, then a concat/interpolation carries the payload. One optional
# intermediate token covers the `env bash -c …` / `node --flag -e …` shapes.
_INLINE_HEAD = (
    r"(?<![.\w$])" + _CP_ALT + r"\s*\(\s*['\"\x60]\s*" + _SHELL_ALT
    + r"(?:\s+[^\s'\"\x60]{1,20})?\s+" + _FLAG_ALT + r"\b")

# NESTED decode directly in the shell payload position — self-evident, no blob corroborator needed
# (running a freshly-decoded value as a shell command is the dropper regardless of blob length).
_SHELL_ARGV_NESTED = re.compile(_ARGV_HEAD + _obf._DECODE, re.IGNORECASE)
_SHELL_INARRAY_NESTED = re.compile(_INARRAY_HEAD + _obf._DECODE, re.IGNORECASE)
_SHELL_INLINE_NESTED = re.compile(
    _INLINE_HEAD + r"[^'\"\x60\n]{0,80}['\"]?\s*(?:\+|\$\{)\s*" + _obf._DECODE, re.IGNORECASE)
_SHELL_NESTED = (_SHELL_ARGV_NESTED, _SHELL_INARRAY_NESTED, _SHELL_INLINE_NESTED)

# VARIABLE at the shell payload position — capture the identifier so we can confirm it is a decode
# var, in scope (corroborated by a baked blob at the call site in `detect_dropper`). The tail allows
# a bounded string-method chain (`d.toString('utf8')`) but not a bare property (a decoded value used
# directly); bounded repetition + inner length keep it linear (test_redos_safety).
_IDENT = r"([A-Za-z_$][\w$]*)"
_VAR_TAIL = r"\s*(?:\.\s*\w+\s*\([^)\n]{0,80}\)){0,4}\s*[,\]]"
_SHELL_ARGV_VAR = re.compile(_ARGV_HEAD + _IDENT + _VAR_TAIL, re.IGNORECASE)
_SHELL_INARRAY_VAR = re.compile(_INARRAY_HEAD + _IDENT + _VAR_TAIL, re.IGNORECASE)
_SHELL_INLINE_VAR = re.compile(
    _INLINE_HEAD + r"[^'\"\x60\n]{0,80}(?:['\"]\s*\+\s*|\$\{\s*)" + _IDENT, re.IGNORECASE)
_SHELL_VAR = (_SHELL_ARGV_VAR, _SHELL_INARRAY_VAR, _SHELL_INLINE_VAR)


def _decode_var_names(view: str) -> set[str]:
    """The set of variables assigned a base64/hex decode (`const d = Buffer.from(p,'base64')`),
    bounded, over the (fully-scrubbed) view — the taint seeds for the variable forms."""
    names: set[str] = set()
    for i, m in enumerate(_obf._DECODE_TO_VAR.finditer(view)):
        if i >= _obf._MAX_DECODE_VARS:
            break
        names.add(m.group(1))
    return names


def _var_reaches_shell(text: str) -> bool:
    """True if a decode-variable reaches a shell code position (argv `-c` slot or inline concat), in
    scope. The scrubber preserves length/offsets, so we match the shell SINK on the strings-KEPT view
    (the `'sh'`/`'-c'` literals must survive) but run the SCOPE/re-bind checks on the strings-BLANKED
    view at the same offsets (so a `}` or `(param)` inside a string can't skew scope) — mirroring the
    discipline of `_decode_var_into_exec`."""
    kept = _obf._scrub_comments_and_strings(text, scrub_strings=False)
    full = _obf._scrub_comments_and_strings(text)          # strings blanked; same length/offsets
    decode_vars = _decode_var_names(full)
    if not decode_vars:
        return False
    for rx in _SHELL_VAR:
        for m in rx.finditer(kept):
            name = m.group(1)
            if name not in decode_vars:
                continue
            assign = _last_decode_assign_before(full, name, m.start())   # decode assign is code
            if assign is None:
                continue
            gap = full[assign:m.start()]
            if _obf._name_rebound(gap, re.escape(name)) or _scope_closed(gap):
                continue
            return True
    return False


def _last_decode_assign_before(view: str, name: str, pos: int) -> int | None:
    """End offset of the nearest `<name> = <decode>` assignment before `pos`, else None."""
    best = None
    pat = re.compile(
        r"(?:(?:const|let|var)\s+)?(?<![.\w$])" + re.escape(name) + r"\s*=(?!=)\s*" + _obf._DECODE)
    for m in pat.finditer(view, 0, pos):
        best = m.end()
    return best


def _scope_closed(gap: str) -> bool:
    """True if the decode's block closes before the sink (brace depth goes negative) — a collision."""
    depth = 0
    for ch in gap:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return True
    return False


def detect_dropper(text: str) -> str | None:
    """Return a redaction-safe reason if `text` contains a baked encoded-payload → decode → exec
    dropper flow, else None. Consolidates the leading-argument forms (reused verbatim from the
    hardened obfuscation arms) and the shell code-argument forms (this module). Static-only."""
    if not text:
        return None

    # 1) Leading-argument forms — REUSE the shipped, 4-round-hardened detection (zero regression):
    #    a nested decode in a command/module/worker sink (self-evident), or a decode-through-variable
    #    reaching such a sink corroborated by a baked blob.
    if _obf._DECODE_INTO_EXEC.search(text):
        return _R_DIRECT
    deassetted = _obf._DATA_URI.sub("", text)
    baked = _obf._has_encoded_payload(_obf._dechunk(deassetted))
    if baked and _obf._decode_var_into_exec(text):
        return _R_VAR

    # 2) Shell code-argument forms — the gap the leading-arg anchor misses. A decoded value in a
    #    shell `-c` slot has no benign analogue. Nested decode is self-evident; the variable form is
    #    blob-corroborated + scope-guarded (a decoded value must reach the shell code slot, in scope).
    kept = _obf._scrub_comments_and_strings(text, scrub_strings=False)  # keep the 'sh'/'-c' literals
    if any(rx.search(kept) for rx in _SHELL_NESTED):
        return _R_SHELL
    if baked and _var_reaches_shell(text):
        return _R_SHELL
    return None
