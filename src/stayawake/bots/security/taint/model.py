#!/usr/bin/env python3
"""The decode→exec DROPPER model — the single, backend-agnostic definition of *what we detect*.

Scope (deliberately narrow — this is a worm detector, not a JS security linter). `saw` catches a
supply-chain worm's **baked-in dropper** in HAND-AUTHORED source: a concealed payload that is

    encoded at rest  →  decoded at runtime  →  executed.

That is the whole target. This module names the three parts of that flow as data — the single source
of truth for "what a dropper looks like" — which the ONE analyzer (`analyzer.py`) consumes. Splitting
the *taxonomy* (here) from the *tracing* (there) keeps the detector one coherent capability while
letting the flow logic evolve without redefining the threat. Everything here is a name/shape table
plus tiny predicates; the regex/scope tracing lives in the analyzer.

What this is NOT (kept out on purpose, so the model stays true to the threat):
  * NOT a runtime command-injection / RCE detector — `execSync(userInput)` with no BAKED payload is a
    vulnerability, not a shipped worm. We require a decoded BAKED blob at the source of the flow.
  * NOT whole-program / cross-file dataflow — a loader whose exec lives in another file is the
    CONFIRMED loader-fingerprint tier's job, not this heuristic's.
  * NOT a verdict of INFECTED — everything here is HEURISTIC → SUSPICIOUS, a corroborator.

The verdict rule both backends share: flag iff a DECODE SOURCE (of a baked blob) reaches a CODE
POSITION of an EXEC SINK via the allowed PROPAGATION forms. Source alone (a lone blob / a JWT decode)
is data; sink alone (a normal `execSync('npm run build')`) is ordinary code; only the FLOW is the
dropper.
"""
from __future__ import annotations

# ── 1. DECODE SOURCES ────────────────────────────────────────────────────────────────────────────
# A call that turns a baked encoded blob into runnable bytes/text. The blob itself (base64/hex/
# charcode/escape) is matched by flow._has_encoded_payload / obfuscation _NUM_ARRAY / _escape_run — this
# names the DECODE step. `Buffer.from` only counts as a decode when its encoding arg is base64/hex
# (a `Buffer.from(str)` / `Buffer.from(arr)` without an encoding is a plain buffer, still a decode of
# a byte array when fed a numeric array — handled by the charcode source below).
DECODE_CALLS = frozenset({"atob", "Buffer.from"})
DECODE_ENCODINGS = frozenset({"base64", "hex", "base64url"})
# Charcode/codepoint reconstruction — `String.fromCharCode(...)` / `.fromCodePoint(...)` fed a
# numeric array is the classic "no greppable literal" decode.
CHARCODE_DECODES = frozenset({"fromCharCode", "fromCodePoint"})

# ── 2. EXEC SINKS ────────────────────────────────────────────────────────────────────────────────
# Points that run a value as CODE or a COMMAND. For each we record which ARGUMENT POSITION is the
# "code position" — the slot where a decoded value means execution (0 = first argument). The whole
# accuracy story of the shell case lives here: a child_process runner's code slot is arg 0 (the
# program) UNLESS arg 0 is a shell interpreter, in which case the code slot is the argument that
# follows a shell code-flag (`-c` / `/c` / `-Command` / …). That is why "a decoded value in args[]"
# is NOT blindly a sink — only the shell code-flag slot is.

# Direct code-evaluation sinks — the decoded value is source code. Code position: arg 0.
CODE_EVAL_SINKS = frozenset({
    "eval",              # eval(decoded)
    "Function",          # Function(decoded) / new Function(decoded)
    "runInContext", "runInNewContext", "runInThisContext",   # vm.* code runners
    "_compile",          # Module.prototype._compile(decoded, filename) — internal compile
})
# Dynamic module / worker load — the decoded value is a specifier or worker source. Code position: 0.
MODULE_SINKS = frozenset({
    "import",            # dynamic import(decoded) — incl. data: JS URIs
    "Worker",            # new Worker(decoded, {eval:true}) / new Worker('data:…')
})
# child_process command runners. Code position: arg 0 (the program), OR the shell code-flag slot when
# arg 0 is a shell interpreter (see SHELL_INTERPRETERS / SHELL_CODE_FLAGS). A regex `.exec` / an event
# `.spawn` share NONE of the -Sync/-File names below except bare `exec`/`spawn`/`fork`; a backend must
# therefore only treat these as command runners on a child_process/shelljs receiver (never bare, to
# avoid the RegExp.exec / EventEmitter collisions).
CP_RUNNERS = frozenset({
    "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork",
})
# Modules whose members are command runners (the receiver that disambiguates a bare `.exec` from
# RegExp.exec / a DB `.exec`).
CP_MODULES = frozenset({"child_process", "node:child_process", "shelljs"})

# Command/code INTERPRETERS: when one of these is the PROGRAM of a command runner, the real command is
# not arg 0 (the interpreter) but the argument following a code-flag — so a decoded value there is the
# dropper's payload. These are BASENAMES; a backend matches them with an optional path prefix
# (`/opt/homebrew/bin/bash` → `bash`) via `is_shell_interpreter` / the analyzer's path-aware regex, so
# absolute paths need not be enumerated. `env` is the wrapper form `env <interp> -c <code>` — the real
# interpreter sits in argv[0] after `env`, which the backend's pre-flag argv scan skips over.
SHELL_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ash", "ksh", "fish",       # POSIX shells
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",  # Windows shells
    "node", "deno", "bun",                                   # JS runtimes: `node -e <decoded>`
    "python", "python2", "python3", "ruby", "perl", "php",   # script interpreters: `python -c`, `perl -e`
    "env",                                                    # wrapper: `env bash -c <decoded>`
})
# The flags that make the FOLLOWING argument executable code for the interpreters above.
SHELL_CODE_FLAGS = frozenset({
    "-c", "/c", "/C", "/k", "/K",                # sh/bash inline command; cmd /c and /k
    "-e", "--eval", "-p", "--print", "-r",       # node/deno -e·-p, ruby/perl -e, php -r
    "-Command", "-EncodedCommand", "-enc",       # powershell inline / base64 command
})

# ── 3. PROPAGATION ───────────────────────────────────────────────────────────────────────────────
# How a decoded value travels from a source to a sink's code position. A backend must honour these
# (and no more — every extra propagation form widens the false-positive surface):
#   * DIRECT          — the decode call is written straight into the code position: `execSync(atob(x))`.
#   * ASSIGN_1HOP     — the decode is assigned to a variable used at the code position within the same
#                       scope: `const d = Buffer.from(p,'base64'); execSync(d)`.
#   * STRING_METHOD   — a chain of string-method calls on the decoded value is transparent:
#                       `d.toString('utf8').trim()`. A bare PROPERTY access (`d.cmd`) is NOT (that
#                       means `d` is a structured object, not decoded bytes).
#   * CONCAT_TEMPLATE — the decoded value concatenated / interpolated into a command string:
#                       `execSync('sh -c ' + d)` / `` execSync(`sh -c ${d}`) ``.
# Multi-hop reassignment (`d=…; c=d; sink(c)`), interprocedural pass-through, and property/collection
# storage are the DOCUMENTED residuals — the textual backend cannot see them scope-correctly, and even
# the AST backend bounds interprocedural depth; both defer that tail to the CONFIRMED tier.
PROPAGATION_DIRECT = "direct"
PROPAGATION_ASSIGN_1HOP = "assign-1hop"
PROPAGATION_STRING_METHOD = "string-method"
PROPAGATION_CONCAT_TEMPLATE = "concat-template"


def is_decode_encoding(enc: str) -> bool:
    """True if `enc` (a Buffer.from second-arg literal, quotes already stripped) is an encoding that
    turns text into bytes we'd then run — base64 / hex / base64url. `utf8`/`ascii`/`latin1` are plain
    text conversions, not a concealment decode, so they do NOT qualify on their own."""
    return enc.strip().lower() in DECODE_ENCODINGS


def is_shell_interpreter(program: str) -> bool:
    """True if `program` (a string literal, quotes stripped) is a shell/interpreter whose real command
    is a following code-flag argument rather than arg 0. Basename-aware so `/opt/homebrew/bin/bash`
    matches via its `bash` tail."""
    p = program.strip().strip("\"'").lower()
    if p in SHELL_INTERPRETERS:
        return True
    tail = p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return tail in SHELL_INTERPRETERS


# ── 4. DESTRUCTIVE-WIPE CAPABILITY (#1334) ──────────────────────────────────────────────────────
# The worm's self-destruct / evidence-removal routine: a recursive filesystem walk ROOTED AT THE USER'S
# HOME (or the filesystem root) co-occurring with DELETION — and, reported distinctly, with OVERWRITE-
# then-delete (a SECURE wipe that makes the data unrecoverable). Detection is a CORROBORATED co-occurrence
# (home-root ∧ recursive ∧ delete): each half alone is common and inert (a scoped `rm -rf ./dist`, a lone
# `unlink(tmp)`, a `readdir` for config); only the COMBINATION is near-zero benign, which is exactly what
# earns the confirmed grade. This is vocabulary only — `destructive.py` compiles the recognisers and a
# differential test pins them to these sets, so the two can never drift.

# The traversal ROOT that turns a recursive delete catastrophic — the user's home, or `/`.
HOME_ROOT_TOKENS = frozenset({
    "os.homedir", "homedir", "expanduser", "Path.home",
    "process.env.HOME", "process.env.USERPROFILE", "process.env.HOMEPATH",
    "$HOME", "${HOME}", "%USERPROFILE%", "~/",
})
# RECURSIVE traversal / recursive-delete markers. A recursive-delete API (rimraf, `rm -rf`, rmSync with
# `recursive:true`) is BOTH the walk and the delete in one call.
RECURSIVE_TOKENS = frozenset({
    "recursive:true", "rimraf", "rm -rf", "rm -fr", "readdir", "readdirSync", "walk", "glob", "**",
    "find ",
})
# DELETION sinks.
DELETE_TOKENS = frozenset({"unlink", "unlinkSync", "rmSync", "rmdirSync", "rmdir", "rimraf", "rm "})
# OVERWRITE-then-delete = the SECURE, unrecoverable variant (bytes overwritten before unlink).
OVERWRITE_TOKENS = frozenset({
    "writeFileSync", "writeFile", "randomBytes", "randomFillSync", "createWriteStream", "shred",
    "dd if=/dev/urandom", "dd if=/dev/zero",
})
# DEAD-MAN'S-SWITCH amplifier: the wipe is armed on an auth/token condition (Shai-Hulud wipes when it
# CANNOT authenticate to GitHub / on token revocation). Co-presence RAISES confidence, never gates.
DEADMAN_TOKENS = frozenset({
    "GITHUB_TOKEN", "NPM_TOKEN", "revoke", "unauthorized", "authenticat", "getUser", "createRepo",
})
