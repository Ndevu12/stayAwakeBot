#!/usr/bin/env python3
"""Primitives the dropper analyzer is built from.

Compiled patterns and small scope-aware predicates over a chunk of source text. Every public helper
here is pure and side-effect free: text in, boolean or match out.
"""
from __future__ import annotations

import re

from stayawake.bots.security.sourcescan import _shannon
from stayawake.bots.security.taint import model


def _name_alt(names) -> str:
    """A non-capturing alternation of call names as they appear in source — each name's dotted parts
    joined by optional whitespace (`Buffer.from` → `Buffer\\s*\\.\\s*from`), longest-first so a longer
    name wins over a prefix (`execFileSync` before `execFile`). Built FROM the `model` frozensets so
    the threat taxonomy has ONE source of truth: adding a runner/decode to the model updates every
    regex here automatically. The `test_taint_model_derivation` equivalence test pins that the derived
    alternations match exactly the shapes the hand-written literals did (no coverage drift)."""
    parts = [r"\s*\.\s*".join(re.escape(p) for p in n.split("."))
             for n in sorted(names, key=len, reverse=True)]
    return "(?:" + "|".join(parts) + ")"


# ── Decode-then-exec dropper (#1266) ──────────────────────────────────────────────
_DECODE = _name_alt(model.DECODE_CALLS) + r"\s*\("
_DECODE_INTO_EXEC = re.compile(
    r"\b(?:execSync|execFileSync|execFile|spawnSync|spawn|fork)\s*\(\s*" + _DECODE
    + r"|\bimport\s*\(\s*" + _DECODE
    + r"|\bnew\s+Worker\s*\(\s*" + _DECODE,
    re.IGNORECASE,
)

# ── #1208 residual (after #1206 + #1266), TIGHTENED per #1289 ──────────────────────
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
    + r"|(?=[^\s])(?![\"'`]|/\*)"
    + r")",
    re.IGNORECASE,
)
_CP_RUNNERS = _name_alt(model.CP_RUNNERS - {"exec"})
_CONSTRUCTED_CP = re.compile(
    # Runner names are child_process-specific (no regex.exec collision). The
    # require('…').exec form uses a quoted-module wildcard so it still matches after
    # the comment/'/-string scrub blanks the module-name characters (quotes remain).
    r"(?<![.\w$])" + _CP_RUNNERS + r"\s*\(\s*" + _CONSTRUCTED_ARG
    + r"|\brequire\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*[\"'][^\"'\n]{1,64}[\"']\s*\)\s*"
    + r"(?:\?\s*)?\.\s*exec(?:Sync)?\s*\(\s*(?:" + _CONSTRUCTED_ARG + r"|" + _DECODE + r")",
    re.IGNORECASE,
)
_DATA_URI_IMPORT = re.compile(
    r"(?<![.\w$])import\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*['\"\x60]\s*data:"
    r"[^'\"\x60\n]{0,80}?(?:java|ecma)script[^'\"\x60\n]{0,40}?;base64,",
    re.IGNORECASE,
)
_CP_METHOD = _name_alt(model.CP_RUNNERS)
_REQUIRE_CP_DECODE = re.compile(
    r"\brequire\s*\(\s*(?:/\*[\s\S]{0,200}?\*/\s*)*['\"](?:node:)?(?:child_process|shelljs)['\"]\s*\)\s*"
    r"(?:\?\s*)?\.\s*" + _CP_METHOD + r"\s*\(\s*" + _DECODE,
    re.IGNORECASE,
)
_TIGHT_DYNEXEC_ANCHORS = ("data:", "child_process", "shelljs")
_TIGHT_DYNEXEC_ANCHOR_RE = re.compile("|".join(re.escape(a) for a in _TIGHT_DYNEXEC_ANCHORS),
                                      re.IGNORECASE)


# ── Variable-indirected decode→exec dropper (#1266 residual; restores the #1212 base64 arm,
#    TIGHTENED so it can never FP on a lone blob) ─────────────────────────────────────────────
# hardcoded base64 payload decoded through a VARIABLE and then run —
#     const p = '<blob>'; const d = Buffer.from(p, 'base64'); execSync(d);
# Neither half is a signal alone: the blob at rest is ubiquitous benign DATA (JWT / API token /
# SRI hash / cert-pin·JWKS key array / crypto KAT / inlined asset) — flagging it standalone is the
# two together: an encoded blob is present AND a decode result flows into a command/module/worker
# never a standalone verdict. This also stays inside saw's baked-payload threat model: requiring a
# hardcoded blob means a `Buffer.from(networkInput); execSync(…)` runtime-RCE (no baked blob) is left
# to other tooling rather than false-alarming here.

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


_DECODE_TO_VAR = re.compile(
    r"(?:(?:const|let|var)\s+)?(?<![.\w$])([A-Za-z_$][\w$]*)\s*=(?!=)\s*" + _DECODE
)
_INDIRECT_SINK_WINDOW = 300
_MAX_DECODE_VARS = 50         # cap the assignments scanned so a hostile file can't blow up the walk


_DECODED_ARG_TAIL = r"\s*(?:\.\s*[\w$]+\s*\([^)]*\))*\s*[,)]"
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
    view = _scrub_comments_and_strings(s)
    for i, m in enumerate(_DECODE_TO_VAR.finditer(view)):
        if i >= _MAX_DECODE_VARS:
            break
        name = re.escape(m.group(1))
        window = view[m.end():m.end() + _INDIRECT_SINK_WINDOW]
        for sm in _sink_takes_var(name).finditer(window):
            gap = window[:sm.start()]
            # (1) Re-binding guard: if the name is re-declared or re-introduced as a function/arrow
            #     PARAMETER before the sink, the sink's variable is a different binding — a name
            #     later `function run(data){ spawn(data,…) }`; a module binding has no `}` to close so
            #     the brace check below can't see it).
            if _name_rebound(gap, name):
                continue
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
    Template literal BODIES are kept intact (the relative-path carve-out must see `./`);
    only `${…}` expression interiors are scrubbed. Best-effort — not a full JS lexer.

    `scrub_strings=False` scrubs comments ONLY, keeping '/\" string contents verbatim. The
    data:-URI-import arm needs this: its tell (`data:…;base64,`) lives INSIDE the specifier
    string, so a full string scrub would blank the very thing it matches — but a mention in a
    // or /* */ comment must still be silenced."""
    out: list[str] = []
    i, n = 0, len(s)
    stack: list[int | None] = []
    while i < n:
        c = s[i]

        if stack and stack[-1] is None:                 # template BODY — data, kept verbatim
            if c == "\\" and i + 1 < n:
                out.append(s[i:i + 2])
                i += 2
                continue
            if c == "`":
                out.append(c)
                stack.pop()
                i += 1
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "{":
                out.append("${")                        # the interior is CODE — fall through to it
                stack.append(0)
                i += 2
                continue
            out.append(c)
            i += 1
            continue

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
            out.append(c)
            stack.append(None)
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
        if stack:                                       # inside an interpolation: track its braces
            if c == "{":
                stack[-1] += 1
            elif c == "}":
                if stack[-1] == 0:
                    out.append(c)
                    stack.pop()
                    i += 1
                    continue
                stack[-1] -= 1
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
    # Prefilter (byte-identical): both TIGHT arms carry a necessary literal — 2a a `data:` URI, 2b a
    # `child_process`/`shelljs` require — so if none of those anchors is present, neither tight arm can
    # match and we skip the comment-scrub + searches. Same re.IGNORECASE folding as the arms → no
    # case-fold asymmetry. (`_TIGHT_DYNEXEC_ANCHOR_RE` mirrors the literals in those two regexes.)
    if _TIGHT_DYNEXEC_ANCHOR_RE.search(s):
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
