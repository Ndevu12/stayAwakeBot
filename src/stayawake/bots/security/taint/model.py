#!/usr/bin/env python3
"""Vocabulary for the decode-then-execute dropper the scanner looks for.

Data only — the token sets and the small predicates over them. `analyzer` consumes these; nothing
here reads source or reaches the filesystem. Keeping the vocabulary in one module is what lets the
analyzer change without redefining what is being detected.
"""
from __future__ import annotations

# ── 1. DECODE SOURCES ────────────────────────────────────────────────────────────────────────────
DECODE_CALLS = frozenset({"atob", "Buffer.from"})
DECODE_ENCODINGS = frozenset({"base64", "hex", "base64url"})
CHARCODE_DECODES = frozenset({"fromCharCode", "fromCodePoint"})

# ── 2. EXEC SINKS ────────────────────────────────────────────────────────────────────────────────
# Points that run a value as CODE or a COMMAND. For each we record which ARGUMENT POSITION is the
# "code position" — the slot where a decoded value means execution (0 = first argument). The whole
# accuracy story of the shell case lives here: a child_process runner's code slot is arg 0 (the
# program) UNLESS arg 0 is a shell interpreter, in which case the code slot is the argument that
# follows a shell code-flag (`-c` / `/c` / `-Command` / …). That is why "a decoded value in args[]"
# is NOT blindly a sink — only the shell code-flag slot is.

CODE_EVAL_SINKS = frozenset({
    "eval",              # eval(decoded)
    "Function",          # Function(decoded) / new Function(decoded)
    "runInContext", "runInNewContext", "runInThisContext",   # vm.* code runners
    "_compile",          # Module.prototype._compile(decoded, filename) — internal compile
})
MODULE_SINKS = frozenset({
    "import",            # dynamic import(decoded) — incl. data: JS URIs
    "Worker",            # new Worker(decoded, {eval:true}) / new Worker('data:…')
})
CP_RUNNERS = frozenset({
    "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork",
})
CP_MODULES = frozenset({"child_process", "node:child_process", "shelljs"})

SHELL_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ash", "ksh", "fish",       # POSIX shells
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",  # Windows shells
    "node", "deno", "bun",                                   # JS runtimes: `node -e <decoded>`
    "python", "python2", "python3", "ruby", "perl", "php",   # script interpreters: `python -c`, `perl -e`
    "env",                                                    # wrapper: `env bash -c <decoded>`
})
SHELL_CODE_FLAGS = frozenset({
    "-c", "/c", "/C", "/k", "/K",                # sh/bash inline command; cmd /c and /k
    "-e", "--eval", "-p", "--print", "-r",       # node/deno -e·-p, ruby/perl -e, php -r
    "-Command", "-EncodedCommand", "-enc",       # powershell inline / base64 command
})

# ── 3. PROPAGATION ───────────────────────────────────────────────────────────────────────────────
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

HOME_ROOT_TOKENS = frozenset({
    "os.homedir", "homedir", "expanduser", "Path.home",
    "process.env.HOME", "process.env.USERPROFILE", "process.env.HOMEPATH",
    "$HOME", "${HOME}", "%USERPROFILE%", "~/",
})
RECURSIVE_TOKENS = frozenset({
    "recursive:true", "rimraf", "rm -rf", "rm -fr", "readdir", "readdirSync", "walk", "glob", "**",
    "find ",
})
DELETE_TOKENS = frozenset({"unlink", "unlinkSync", "rmSync", "rmdirSync", "rmdir", "rimraf", "rm "})
OVERWRITE_TOKENS = frozenset({
    "writeFileSync", "writeFile", "randomBytes", "randomFillSync", "createWriteStream", "shred",
    "dd if=/dev/urandom", "dd if=/dev/zero",
})
DEADMAN_TOKENS = frozenset({
    "GITHUB_TOKEN", "NPM_TOKEN", "revoke", "unauthorized", "authenticat", "getUser", "createRepo",
})
