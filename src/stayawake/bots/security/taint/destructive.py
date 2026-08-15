#!/usr/bin/env python3
"""Destructive-intent (self-destruct / evidence-removal) detector (#1334).

`saw` already sees that a lifecycle script *runs code*; this sees that the code *deletes the user's home
directory*. The routine has a static shape: a recursive filesystem walk ROOTED AT THE USER'S HOME (or
`/`) co-occurring with DELETION — and, reported DISTINCTLY, with OVERWRITE-then-delete (a secure wipe
that makes the data unrecoverable). That distinction is load-bearing for incident response: plain delete
leaves recoverable content (image the disk now), a secure overwrite does not (the data is gone).

FUSION, not one heuristic (like #1333): the NECESSARY core is the corroborated co-occurrence
(home-root ∧ recursive ∧ delete) — each half alone is common and inert (`rm -rf ./dist`, a lone
`unlink(tmp)`, a `readdir` for config), so nothing fires without all three. On top of that necessary
core we FUSE amplifiers that enrich the verdict and confirm it is the worm and not a coincidence: the
dead-man's-switch trigger (armed on a GitHub-auth / token-revocation condition), a co-present
decode→exec dropper, and the named IoC droppers (`setup_bun.js` / `bun_environment.js`). The core's
near-zero benign use is what earns the confirmed grade; the amplifiers make the evidence unambiguous.

Model-driven and dependency-free (regex over the `model` taxonomy, like `detect_dropper` — no AST
engine). Static: the literal + decode-behind shapes are reachable without process visibility; a fully
computed/obfuscated traversal root, and cross-FILE reach (walk in one file, delete in another), are the
documented residuals.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import model

PLAIN, SECURE = "plain", "secure"

# HOME-ROOT expression, also kept as a raw fragment `_HOME` so we can require it CO-LOCATED with the
# destructive op (the delete/walk is ROOTED AT home) rather than merely PRESENT somewhere in the file —
# the latter would false-positive on `os.homedir()` for a config path + a scoped `rimraf('./dist')`.
# Covers dot AND bracket access (`process.env['HOME']`) so the obvious evasion doesn't slip.
_HOME = (r"(?:\bos\.homedir\s*\(\)|(?<![\w.])homedir\s*\(\)"
         r"|\bexpanduser\s*\(\s*['\"]~|\bPath\.home\s*\(\)"
         r"|\bprocess\.env\.(?:HOME|USERPROFILE|HOMEPATH)\b"
         r"|\bprocess\.env\[\s*['\"](?:HOME|USERPROFILE|HOMEPATH)['\"]\s*\]"
         r"|\$env:(?:USERPROFILE|HOMEPATH|HOME)\b"          # PowerShell env home
         r"|\$\{?HOME\}?|%USERPROFILE%|%HOMEPATH%"          # POSIX / Windows batch env home
         r"|(?<![\w.~/])~(?=[/\s'\"]|$))")     # ~/  and a bare `~` path (rm -rf ~) — not `~x` bitwise-not
_HOME_ROOT = re.compile(_HOME, re.IGNORECASE)

# A recursive delete/walk at the FILESYSTEM ROOT (`/` as the WHOLE argument — never `/tmp/x`).
_ROOT_WIPE = re.compile(
    r"\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+/(?:\s|$|['\"])"          # rm -rf /
    r"|\brimraf\s*\(\s*['\"]/['\"]"                            # rimraf("/")
    r"|\brmSync\s*\(\s*['\"]/['\"]", re.IGNORECASE)

# ── The corroborated core: a destructive op ROOTED AT HOME. The home token must appear INSIDE the
# call, within the SAME statement (`_W`, a bounded/ReDoS-safe window over a delimiter-excluding class).
_W = r"[^;\n]{0,80}?"
# A recursive delete whose target is home — POSIX (rimraf(home) / rm -rf home) and WINDOWS
# (rmdir /s / rd /s / del /s / Remove-Item -Recurse over %USERPROFILE% / $env:USERPROFILE).
_RECURSIVE_DELETE_HOME = re.compile(
    r"(?:\brimraf\s*\(|\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+"
    r"|(?:\brmdir|\brd|\bdel)\s+[^;\n]{0,24}?/s\b)" + _W + _HOME             # POSIX + cmd.exe delete
    + r"|\bRemove-Item\b[^;\n]{0,120}?-Recurse[^;\n]{0,120}?" + _HOME        # PowerShell (flag then home)
    + r"|\bRemove-Item\b[^;\n]{0,120}?" + _HOME + r"[^;\n]{0,120}?-Recurse", # PowerShell (home then flag)
    re.IGNORECASE)
# fs.rmSync(home,{recursive:true}) / fs.rm(home,{recursive:true}) — home AND recursive:true in the call.
_RMSYNC_RECURSIVE_HOME = re.compile(
    r"(?:\brmSync|\bfs\.rm|\brmdirSync)\s*\(" + _W + _HOME + _W + r"recursive\s*:\s*true"
    r"|(?:\brmSync|\bfs\.rm|\brmdirSync)\s*\(" + _W + r"recursive\s*:\s*true" + _W + _HOME,
    re.IGNORECASE)
# A traversal ROOTED AT HOME (readdir/walk/glob/find over home) — pairs with a separate delete sink.
_WALK_HOME = re.compile(
    r"(?:\breaddir(?:Sync)?\s*\(|\bwalk(?:Sync)?\s*\(|\bglob(?:Sync)?\s*\(|\bklaw\s*\("
    r"|\blistdir\s*\(|\bscandir\s*\(|\biterdir\s*\(\s*\)|\bfind\s+)"
    + _W + _HOME, re.IGNORECASE)
# Any deletion sink (only consulted once a home-rooted WALK is established) — incl. shell `find`
# terminals (`find $HOME -delete` / `find $HOME -exec rm`).
_DELETE = re.compile(
    r"\bunlink(?:Sync)?\s*\(|\brmSync\s*\(|\brmdir(?:Sync)?\s*\(|\brimraf\b"
    r"|\bfs\.rm\s*\(|\brm\s+-|-delete\b|-exec\s+\S*\brm\b", re.IGNORECASE)

# OVERWRITE-then-delete → the SECURE, unrecoverable variant.
_OVERWRITE = re.compile(
    r"\bwriteFile(?:Sync)?\s*\(|\brandomBytes\s*\(|\brandomFillSync\s*\(|\bcreateWriteStream\s*\("
    r"|\bshred\b|\bdd\s+if=/dev/(?:urandom|zero)", re.IGNORECASE)

# Amplifiers (raise confidence / enrich — never gate).
_DEADMAN = re.compile(
    r"\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|\brevoke|\bunauthorized\b|\bauthenticat|\bgetUser\b|\bcreateRepo",
    re.IGNORECASE)
_NAMED_IOC = re.compile(r"\b(?:setup_bun|bun_environment)\b", re.IGNORECASE)

# #1336 — the destructive capability shipped behind a DISABLED feature flag (the SANDWORM_MODE staging
# shape: the routine is present + functional, one attacker toggle from running). We deliberately do NOT
# try to resolve the flag's runtime VALUE — that is unreliable, attacker-controlled, and the polymorphic
# engine is itself one of the flagged components. We detect a destruct-intent-NAMED flag DECLARED to a
# disabled value. This is ENRICHMENT ONLY: it changes the finding's WORDING, never the verdict — so an
# undetected gate simply reads as "armed" (the safer default) and the finding stands either way. Bounded
# (no nested quantifier) → ReDoS-safe.
_DESTRUCT_FLAG = r"(?:destroy|destruct|self_?destruct|wipe|nuke|purge|detonat|sandworm|dead_?man|kill_?switch)"
_DISABLED_FLAG = re.compile(
    r"\b\w*" + _DESTRUCT_FLAG + r"\w*\b\s*[:=]\s*(?:false|0|['\"]?(?:off|no|disabled?)['\"]?)\b",
    re.IGNORECASE)



# A name bound to the home directory IS the home directory. Requiring the home token inside the
# delete call meant one assignment defeated the whole arm — `const h = os.homedir()` then
# `rmSync(h, {recursive:true})` went unreported, which is the shortest possible evasion.



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


# A new top-level `def`/`class` ends the walk's scope in Python, where there is no closing brace.
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


# Measured: a walk and the delete it feeds sit 16-1,692 characters apart, the far end being a loop
# with a 120-line body. The co-presence false positive in a real editor bundle sat 336,053 apart — a
# documented shell command and the word "-delete-char" in help text. Scope alone does not separate
# them in a FLAT file with no braces, so distance carries that case.
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
    variant: str            # PLAIN (recoverable) | SECURE (overwrite-then-delete, unrecoverable)
    reason: str             # short, redaction-safe evidence string
    gated: bool = False     # #1336: the capability is PRESENT but guarded behind a DISABLED feature
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
    # A recursive delete ROOTED AT HOME (home is the target of rimraf/`rm -rf`/rmSync-recursive), OR a
    # home-rooted WALK paired with a delete sink. The home token must be CO-LOCATED with the op — not
    # merely present in the file — so a coincidental `os.homedir()` + scoped `rimraf('./dist')` is inert.
    home_recursive_delete = (bool(_RECURSIVE_DELETE_HOME.search(text))
                             or bool(_RMSYNC_RECURSIVE_HOME.search(text))
                             or _recursive_delete_of_home_name(text))
    home_walk_delete = _walks_home_and_deletes(text)
    if not (home_recursive_delete or home_walk_delete or root_wipe):
        return None
    home = home_recursive_delete or home_walk_delete

    overwrite = bool(_OVERWRITE.search(text))
    variant = SECURE if overwrite else PLAIN
    where = "the filesystem root (/)" if (root_wipe and not home) else "the user's home directory"
    destroys = ("OVERWRITES-then-deletes files (secure wipe — data is unrecoverable)" if variant == SECURE
                else "DELETES files (recoverable — image the disk before use)")
    # #1336 — capability-first: the finding is on the routine's PRESENCE, never its reachability. When
    # the routine is gated behind a DISABLED feature flag it is still CONFIRMED (never downgraded) — the
    # flag is attacker-controlled context, so the wording shifts to "contains a … CAPABILITY, gated"
    # rather than the present-tense "wipes …", which is both accurate and more alarming than either half.
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
