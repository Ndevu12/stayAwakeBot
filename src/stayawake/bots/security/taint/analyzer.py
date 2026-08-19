#!/usr/bin/env python3
"""The decode-then-execute dropper analyzer.

`detect_dropper(text)` takes a chunk of hand-authored source and returns a reason string when the
file carries a concealed payload that is decoded and then run, or None. It is the only entry point
callers need; `model` holds the vocabulary and `flow` the primitives.
"""
from __future__ import annotations

import re

from stayawake.bots.security import sourcescan
from stayawake.bots.security.taint import flow, model

_DECODE_ANCHORS = frozenset(name.split(".", 1)[0].lower() for name in model.DECODE_CALLS)
_DECODE_ANCHOR_RE = re.compile("|".join(re.escape(a) for a in sorted(_DECODE_ANCHORS)), re.IGNORECASE)

_R_DIRECT = "base64/hex decoded and run via a command/module sink (child_process/import/Worker)"
_R_VAR = "base64 payload decoded via a variable and run (command/module/worker sink)"
_R_SHELL = "base64/hex decoded and run as a shell command (sh/bash/cmd/powershell -c)"

# ── Shell code-position building blocks (from the model, longest-first so `cmd.exe` beats `cmd`) ──
_SHELL_BASE = "(?:" + "|".join(
    re.escape(s) for s in sorted(model.SHELL_INTERPRETERS, key=len, reverse=True)) + ")"
_SHELL_ALT = r"(?:[^'\"\x60\s]{0,80}[/\\])?" + _SHELL_BASE
_FLAG_ALT = "(?:" + "|".join(
    re.escape(f) for f in sorted(model.SHELL_CODE_FLAGS, key=len, reverse=True)) + ")"
_CP_ALT = "(?:" + "|".join(sorted(model.CP_RUNNERS, key=len, reverse=True)) + ")"

_ARGV_HEAD = (
    r"(?<![.\w$])" + _CP_ALT + r"\s*\(\s*['\"]" + _SHELL_ALT + r"['\"]\s*,\s*\[[^\]\n]{0,120}?"
    r"['\"]" + _FLAG_ALT + r"['\"]\s*,\s*")
_INARRAY_HEAD = (
    r"\[\s*['\"]" + _SHELL_ALT + r"['\"]\s*,\s*[^\]\n]{0,80}?['\"]" + _FLAG_ALT + r"['\"]\s*,\s*")
_INLINE_HEAD = (
    r"(?<![.\w$])" + _CP_ALT + r"\s*\(\s*['\"\x60]\s*" + _SHELL_ALT
    + r"(?:\s+[^\s'\"\x60]{1,20})?\s+" + _FLAG_ALT + r"\b")

_SHELL_ARGV_NESTED = re.compile(_ARGV_HEAD + flow._DECODE, re.IGNORECASE)
_SHELL_INARRAY_NESTED = re.compile(_INARRAY_HEAD + flow._DECODE, re.IGNORECASE)
_SHELL_INLINE_NESTED = re.compile(
    _INLINE_HEAD + r"[^'\"\x60\n]{0,80}['\"]?\s*(?:\+|\$\{)\s*" + flow._DECODE, re.IGNORECASE)
_SHELL_NESTED = (_SHELL_ARGV_NESTED, _SHELL_INARRAY_NESTED, _SHELL_INLINE_NESTED)

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
    for i, m in enumerate(flow._DECODE_TO_VAR.finditer(view)):
        if i >= flow._MAX_DECODE_VARS:
            break
        names.add(m.group(1))
    return names


def _var_reaches_shell(text: str) -> bool:
    """True if a decode-variable reaches a shell code position (argv `-c` slot or inline concat), in
    scope. The scrubber preserves length/offsets, so we match the shell SINK on the strings-KEPT view
    (the `'sh'`/`'-c'` literals must survive) but run the SCOPE/re-bind checks on the strings-BLANKED
    view at the same offsets (so a `}` or `(param)` inside a string can't skew scope) — mirroring the
    discipline of `_decode_var_into_exec`."""
    kept = flow._scrub_comments_and_strings(text, scrub_strings=False)
    full = flow._scrub_comments_and_strings(text)
    decode_vars = _decode_var_names(full)
    if not decode_vars:
        return False
    for rx in _SHELL_VAR:
        for m in rx.finditer(kept):
            name = m.group(1)
            if name not in decode_vars:
                continue
            assign = _last_decode_assign_before(full, name, m.start())
            if assign is None:
                continue
            gap = full[assign:m.start()]
            if flow._name_rebound(gap, re.escape(name)) or _scope_closed(gap):
                continue
            return True
    return False


def _last_decode_assign_before(view: str, name: str, pos: int) -> int | None:
    """End offset of the nearest `<name> = <decode>` assignment before `pos`, else None."""
    best = None
    pat = re.compile(
        r"(?:(?:const|let|var)\s+)?(?<![.\w$])" + re.escape(name) + r"\s*=(?!=)\s*" + flow._DECODE)
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
    hardened obfuscation arms) and the shell code-argument forms (this module). Static-only.

    A necessary-decode-anchor PREFILTER short-circuits the (expensive) arms — the dominant scan-time
    cost — on the ~all files with no decode. It is byte-identical to running the arms directly (see
    `_run_dropper_arms` + the differential test); every arm requires a `model.DECODE_CALLS` decode."""
    if not text:
        return None
    # Prefilter: same re.IGNORECASE folding as flow._DECODE → a provably necessary condition (no
    # case-fold asymmetry). If no decode anchor can appear, no arm can fire.
    if not _DECODE_ANCHOR_RE.search(text):
        return None
    return _run_dropper_arms(text)


def _run_dropper_arms(text: str) -> str | None:
    """The dropper arms WITHOUT the prefilter — the un-gated reference `detect_dropper` must equal.
    Kept separate so a differential/fuzz test can pin the invariant that every arm requires a decode
    anchor (so the gate can never silently drop a future arm). Do not call directly on the hot path."""
    # 1) Leading-argument forms — REUSE the shipped, 4-round-hardened detection (zero regression):
    #    a nested decode in a command/module/worker sink (self-evident), or a decode-through-variable
    #    reaching such a sink corroborated by a baked blob.
    if flow._DECODE_INTO_EXEC.search(text):
        return _R_DIRECT
    deassetted = sourcescan._DATA_URI.sub("", text)
    baked = flow._has_encoded_payload(sourcescan._dechunk(deassetted))
    if baked and flow._decode_var_into_exec(text):
        return _R_VAR

    kept = flow._scrub_comments_and_strings(text, scrub_strings=False)
    if any(rx.search(kept) for rx in _SHELL_NESTED):
        return _R_SHELL
    if baked and _var_reaches_shell(text):
        return _R_SHELL
    return None
