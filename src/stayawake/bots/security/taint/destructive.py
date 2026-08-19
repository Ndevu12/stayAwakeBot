#!/usr/bin/env python3
"""Detector for code whose purpose is to destroy the user's files.

`detect_destructive(text)` returns a finding reason when a chunk of source carries a routine that
deletes a user's home directory, and distinguishes a plain delete from one that overwrites first.
Returns None otherwise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import model

PLAIN, SECURE = "plain", "secure"

_HOME = (r"(?:\bos\.homedir\s*\(\)|(?<![\w.])homedir\s*\(\)"
         r"|\bexpanduser\s*\(\s*['\"]~|\bPath\.home\s*\(\)"
         r"|\bprocess\.env\.(?:HOME|USERPROFILE|HOMEPATH)\b"
         r"|\bprocess\.env\[\s*['\"](?:HOME|USERPROFILE|HOMEPATH)['\"]\s*\]"
         r"|\$env:(?:USERPROFILE|HOMEPATH|HOME)\b"          # PowerShell env home
         r"|\$\{?HOME\}?|%USERPROFILE%|%HOMEPATH%"          # POSIX / Windows batch env home
         r"|(?<![\w.~/])~(?=[/\s'\"]|$))")     # ~/  and a bare `~` path (rm -rf ~) — not `~x` bitwise-not
_HOME_ROOT = re.compile(_HOME, re.IGNORECASE)

_ROOT_WIPE = re.compile(
    r"\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+/(?:\s|$|['\"])"          # rm -rf /
    r"|\brimraf\s*\(\s*['\"]/['\"]"                            # rimraf("/")
    r"|\brmSync\s*\(\s*['\"]/['\"]", re.IGNORECASE)

# ── The corroborated core: a destructive op ROOTED AT HOME. The home token must appear INSIDE the
_W = r"[^;\n]{0,80}?"
_RECURSIVE_DELETE_HOME = re.compile(
    r"(?:\brimraf\s*\(|\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+"
    r"|(?:\brmdir|\brd|\bdel)\s+[^;\n]{0,24}?/s\b)" + _W + _HOME             # POSIX + cmd.exe delete
    + r"|\bRemove-Item\b[^;\n]{0,120}?-Recurse[^;\n]{0,120}?" + _HOME        # PowerShell (flag then home)
    + r"|\bRemove-Item\b[^;\n]{0,120}?" + _HOME + r"[^;\n]{0,120}?-Recurse", # PowerShell (home then flag)
    re.IGNORECASE)
_RMSYNC_RECURSIVE_HOME = re.compile(
    r"(?:\brmSync|\bfs\.rm|\brmdirSync)\s*\(" + _W + _HOME + _W + r"recursive\s*:\s*true"
    r"|(?:\brmSync|\bfs\.rm|\brmdirSync)\s*\(" + _W + r"recursive\s*:\s*true" + _W + _HOME,
    re.IGNORECASE)
_WALK_HOME = re.compile(
    r"(?:\breaddir(?:Sync)?\s*\(|\bwalk(?:Sync)?\s*\(|\bglob(?:Sync)?\s*\(|\bklaw\s*\("
    r"|\blistdir\s*\(|\bscandir\s*\(|\biterdir\s*\(\s*\)|\bfind\s+)"
    + _W + _HOME, re.IGNORECASE)
_DELETE = re.compile(
    r"\bunlink(?:Sync)?\s*\(|\brmSync\s*\(|\brmdir(?:Sync)?\s*\(|\brimraf\b"
    r"|\bshutil\s*\.\s*rmtree\s*\(|\bremovedirs\s*\(|\bos\s*\.\s*remove\s*\("
    r"|\bfs\.rm\s*\(|\brm\s+-|-delete\b|-exec\s+\S*\brm\b", re.IGNORECASE)

_OVERWRITE = re.compile(
    r"\bwriteFile(?:Sync)?\s*\(|\brandomBytes\s*\(|\brandomFillSync\s*\(|\bcreateWriteStream\s*\("
    r"|\bshred\b|\bdd\s+if=/dev/(?:urandom|zero)", re.IGNORECASE)

_DEADMAN = re.compile(
    r"\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|\brevoke|\bunauthorized\b|\bauthenticat|\bgetUser\b|\bcreateRepo",
    re.IGNORECASE)
_NAMED_IOC = re.compile(r"\b(?:setup_bun|bun_environment)\b", re.IGNORECASE)

_DESTRUCT_FLAG = r"(?:destroy|destruct|self_?destruct|wipe|nuke|purge|detonat|sandworm|dead_?man|kill_?switch)"
_DISABLED_FLAG = re.compile(
    r"\b\w*" + _DESTRUCT_FLAG + r"\w*\b\s*[:=]\s*(?:false|0|['\"]?(?:off|no|disabled?)['\"]?)\b",
    re.IGNORECASE)



# A name bound to the home directory IS the home directory. Requiring the home token inside the
# delete call meant one assignment defeated the whole arm — `const h = os.homedir()` then



def _recursive_delete_of_home_name(text: str) -> bool:
    """A recursive delete whose target is a name that STILL holds the home directory there.

    Binding matters, not co-presence: `result = os.path.expanduser('~')` appears in ordinary library
    code where `result` is then reused for a dozen unrelated values. Measured on pip's vendored
    distlib, matching any later delete of that name produced a false positive. So the binding must be
    the NEAREST one before the delete, must not be rebound in between, and its block must not have
    closed — the same discipline the decode-to-exec analyzer applies to its own variables."""
    deletes = (
        r"(?:\brimraf\s*\(|\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+)" + _W + r"([A-Za-z_$][\w$]*)\b",
        r"(?:\brmSync|\bfs\.rm|\brmdirSync)\s*\(" + _W + r"([A-Za-z_$][\w$]*)\b" + _W
        + r"recursive\s*:\s*true",
        r"\bshutil\.rmtree\s*\(\s*\$?\{?([A-Za-z_$][\w$]*)\b",
    )
    for pattern in deletes:
        for hit in re.finditer(pattern, text, re.IGNORECASE):
            name = hit.group(1)
            bind = _last_home_binding_before(text, name, hit.start())
            if bind is None:
                continue
            gap = text[bind:hit.start()]
            if _rebound(gap, name) or not _same_scope(gap):
                continue
            return True
    return False


def _last_home_binding_before(text: str, name: str, pos: int) -> int | None:
    """End offset of the nearest `<name> = <home expression>` before `pos`, else None."""
    binding = re.compile(r"(?:(?:const|let|var)\s+)?(?<![.\w$])" + re.escape(name)
                         + r"\s*=(?!=)\s*" + _W + _HOME, re.IGNORECASE)
    last = None
    for m in binding.finditer(text, 0, pos):
        last = m.end()
    return last


def _rebound(gap: str, name: str) -> bool:
    """The name was assigned something else between the binding and the delete."""
    return bool(re.search(r"(?<![.\w$])" + re.escape(name) + r"\s*=(?!=)", gap))


_NEW_TOPLEVEL_DEF = re.compile(r"^(?:def|class)\s", re.MULTILINE)


def _same_scope(gap: str) -> bool:
    """Whether a delete found after a home walk is still INSIDE the walk's scope.

    The arm asks whether this file walks home and deletes what it finds. Searching the whole file for
    a delete answers a different question — co-presence — so a dotfile manager that lists `$HOME` in
    one function and unlinks a temp file in another graded INFECTED.

    Braces only: the walk match ends inside its own call, so counting `(` would read that call's own
    `)` as the scope ending and reject every true positive. Parenthesis nesting is not scope."""
    depth = 0
    for ch in gap:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
    return not _NEW_TOPLEVEL_DEF.search(gap)


_JS_CALLABLE = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b|\()", re.IGNORECASE)
_PY_CALLABLE = re.compile(r"^([ \t]*)def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
_MAX_CALLABLES = 200
_WIRING_WINDOW = 300


def _callable_bodies(text: str) -> list[tuple[str, str]]:
    """(name, body) for named callables — brace-matched for JS, indentation-bounded for Python."""
    bodies: list[tuple[str, str]] = []
    for m in _JS_CALLABLE.finditer(text):
        name = m.group(1) or m.group(2)
        brace = text.find("{", m.end())
        if name is None or brace == -1 or brace - m.end() > 200:
            continue
        depth, i = 0, brace
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        bodies.append((name, text[brace:i]))
        if len(bodies) >= _MAX_CALLABLES:
            return bodies
    for m in _PY_CALLABLE.finditer(text):
        indent, name = m.group(1), m.group(2)
        rest = text[m.end():]
        end = len(rest)
        for line in re.finditer(r"^(?![ \t]*(?:#|$))([ \t]*)\S", rest, re.MULTILINE):
            if len(line.group(1)) <= len(indent) and line.start() > 0:
                end = line.start()
                break
        bodies.append((name, rest[:end]))
        if len(bodies) >= _MAX_CALLABLES:
            break
    return bodies


def _walk_result_reaches_a_deleter(text: str) -> bool:
    """A function that walks home whose RESULT is handed to a function that deletes."""
    walkers, deleters = [], []
    for name, body in _callable_bodies(text):
        if _WALK_HOME.search(body):
            walkers.append(name)
        elif _DELETE.search(body):
            deleters.append(name)
    if not walkers or not deleters:
        return False
    deleter_alt = "(?:" + "|".join(re.escape(d) for d in deleters[:40]) + r")\b"
    for walker in walkers[:40]:
        call = re.compile(r"(?<!function )(?<!def )\b" + re.escape(walker) + r"\s*\(")
        for hit in call.finditer(text):
            window = text[hit.end():hit.end() + _WIRING_WINDOW]
            if re.search(deleter_alt, window):
                return True
    return False


_MAX_WALK_TO_DELETE = 4_000


def _walks_home_and_deletes(text: str) -> bool:
    """A home-rooted walk with a delete still in its scope — checked at EVERY walk, since an early
    unrelated one must not decide the file."""
    for walk in _WALK_HOME.finditer(text):
        for delete in _DELETE.finditer(text, walk.end()):
            gap = text[walk.end():delete.start()]
            if len(gap) > _MAX_WALK_TO_DELETE:
                break                       # deletes are found in order; the rest are further still
            if _same_scope(gap):
                return True
    return False


@dataclass
class DestructiveVerdict:
    variant: str
    reason: str
    gated: bool = False
                            # flag (still a confirmed finding — never a downgrade; the flag is context)


def _amplifiers(text: str) -> list[str]:
    extra: list[str] = []
    if _DEADMAN.search(text):
        extra.append("armed on a GitHub-auth / token-revocation condition (dead-man's-switch)")
    if _NAMED_IOC.search(text):
        extra.append("carries a named Shai-Hulud dropper (setup_bun/bun_environment)")
    try:                                            # co-present decode→exec dropper (lazy: avoid cycle)
        from .analyzer import detect_dropper
        if detect_dropper(text):
            extra.append("co-located with a decode→execute dropper")
    except Exception:                               # noqa: BLE001 — an amplifier must never break detection
        pass
    return extra


def detect_destructive(text: str) -> DestructiveVerdict | None:
    """Return a DestructiveVerdict when `text` recursively walks the user's home (or `/`) AND deletes —
    the corroborated core — else None. SECURE when it overwrites-then-deletes. Amplifiers enrich the
    reason but are never required. FP-safe by the home-root ∧ recursive ∧ delete corroboration."""
    if not text:
        return None
    root_wipe = bool(_ROOT_WIPE.search(text))
    home_recursive_delete = (bool(_RECURSIVE_DELETE_HOME.search(text))
                             or bool(_RMSYNC_RECURSIVE_HOME.search(text))
                             or _recursive_delete_of_home_name(text))
    home_walk_delete = _walks_home_and_deletes(text) or _walk_result_reaches_a_deleter(text)
    if not (home_recursive_delete or home_walk_delete or root_wipe):
        return None
    home = home_recursive_delete or home_walk_delete

    overwrite = bool(_OVERWRITE.search(text))
    variant = SECURE if overwrite else PLAIN
    where = "the filesystem root (/)" if (root_wipe and not home) else "the user's home directory"
    destroys = ("OVERWRITES-then-deletes files (secure wipe — data is unrecoverable)" if variant == SECURE
                else "DELETES files (recoverable — image the disk before use)")
    gated = bool(_DISABLED_FLAG.search(text))
    if gated:
        head = (f"contains a routine that recursively walks {where} and {destroys} — a self-destruct "
                "CAPABILITY currently GATED behind a disabled feature flag; an attacker can flip it in "
                "the next publish with no other change (capability is durable, configuration is not — "
                "present but not currently armed; do not dismiss as inactive)")
    else:
        head = f"recursively walks {where} and {destroys}"
    reason = "destructive intent: " + head
    extra = _amplifiers(text)
    if extra:
        reason += "; " + "; ".join(extra)
    return DestructiveVerdict(variant=variant, reason=reason, gated=gated)
