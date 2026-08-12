#!/usr/bin/env python3
"""Autorun GRADING (#1333) — fuse novelty + provenance + content-shape + correlation into one verdict.

No single signal is enough: a signature misses a novel payload; a bare diff alarms on every install; a
bare provenance check flags a legitimately hand-installed agent. Fused, they separate a foothold from a
legit install accurately — and the fusion is what lets a NOVEL payload be flagged without a signature
(it is unattributed, runs from a scratch path, and something new appeared), while a signed package agent
stays quiet even though it, too, is new.

Grades map onto the existing hygiene severities so they flow through #1332's rotation-safety contract:
a high-confidence foothold is a `warning` under `autorun-unattributed-foothold` (an ACTIVE_PERSISTENCE
id → rotation UNSAFE, exit 3); a merely-new unattributed entry is an `info` review item. Novelty NEVER
escalates on its own, and — the load-bearing property — provenance/content/correlation run on EVERY
entry regardless of the baseline, so a tampered or first-run baseline can never launder a foothold.
"""
from __future__ import annotations

import os
import re
import shlex
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils import pathsafe
from ..models import HygieneIssue, POSIX_SHELLS, _WIPER_NOTE
from .. import mechanism
from ...taint import analyzer
from ...taint.destructive import detect_destructive
from .baseline import NEW, CHANGED

_MAX_REFERENCED = 256 * 1024        # cap the referenced-script read — a real dropper is tiny


# Script interpreters: when one of these is argv[0], the real payload is the SCRIPT ARGUMENT, not the
# interpreter binary. A LaunchAgent/unit that runs `node /path/daemon.js` launders provenance through
# the trusted interpreter — the daemon's code is what determines behaviour, so that is what we read.
_INTERPRETERS = frozenset({
    "node", "nodejs", "deno", "bun", "python", "python2", "python3", "ruby", "perl", "php",
    "sh", "bash", "zsh", "dash", "ksh", "osascript", "tsx", "ts-node"})


# Inline-eval flags: the code is IN argv (already seen via `shape_text()`), not in a script file — so
# `node -e '<code>'` / `python -c '<code>'` must NOT mistake the code argument for a path to read.
_INLINE_EVAL_FLAGS = frozenset({"-e", "--eval", "-c", "-p", "--print", "-"})


# Exec wrappers stand BEFORE the real program (`env A=1 bash -c …`, `sudo -u x node app.js`). Resolving
# them is what lets one walk answer for every consumer instead of each guessing from argv[0].
_EXEC_WRAPPERS = frozenset({"env", "sudo", "nohup", "nice", "setsid", "exec", "command", "stdbuf",
                            "time", "doas"})
# Wrapper options that consume the NEXT token. Per wrapper because they conflict: `stdbuf -i` takes a
# value, `env -i` does not. Without this the value reads as the program and `sudo -u nobody sh -c
# <payload>` goes silent — measured on seven wrapper forms.
_WRAPPER_VALUE_OPTS = {
    "sudo":   frozenset({"-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "--close-from",
                         "-h", "--host", "-r", "--role", "-t", "--type", "-U", "--other-user"}),
    "doas":   frozenset({"-u", "-C"}),
    "env":    frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "nice":   frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "--input", "-o", "--output", "-e", "--error"}),
    "time":   frozenset({"-f", "--format", "-o", "--output"}),
}
_SYSTEM_BIN_DIRS = frozenset({"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin",
                              "/opt/homebrew/bin", "/opt/local/bin"})
_ASSIGNMENT = re.compile(r"[A-Za-z_]\w{0,255}=")
# Flags whose ARGUMENT is code rather than a path. `-m` is neither: it names a module.
_CODE_FLAGS = frozenset({"-c", "-e", "--eval", "-p", "--print", "-Command", "-EncodedCommand"})
_MODULE_FLAGS = frozenset({"-m", "--module"})


@dataclass(frozen=True)
class Invocation:
    """What one command line actually executes, resolved ONCE.

    Four consumers used to answer this separately — which file to read, whether referenced content is
    shell, which arguments are code, which lines take shell grammar — from argv[0] or from a regex over
    the joined argv. Four partial answers to one question is how they disagreed (#1393)."""
    interpreter: str | None = None       # the real program, wrappers stripped
    is_posix_shell: bool = False
    payload_path: str | None = None      # the file it executes, if any
    code_args: tuple[str, ...] = ()      # arguments that ARE code, not paths


def resolve_invocation(argv) -> Invocation:
    """Resolve ONE command line. Per command line, never per entry: `entry.argv` is only the first of
    them, and `_invocations` is what covers the rest."""
    argv = list(argv or [])
    if not argv:
        return Invocation()
    i = _program_index(argv)
    # A program is never a bare flag: landing on one means the walk lost the line, so fall back to
    # argv[0] — the un-resolved answer — rather than inventing a payload out of an option.
    if i >= len(argv) or argv[i].startswith("-"):
        return Invocation(interpreter=argv[0], payload_path=argv[0])
    interp, rest = argv[i], argv[i + 1:]
    base = _interpreter_base(interp)
    if base not in _INTERPRETERS:
        return Invocation(interpreter=interp, payload_path=interp)
    code, path = [], None
    for n, arg in enumerate(rest):
        if arg in _CODE_FLAGS:
            if n + 1 < len(rest):
                code.append(rest[n + 1])
            break              # what follows the code is an argument TO it ($0, $@) — never a path
        if arg in _MODULE_FLAGS:
            break              # a module NAME, and what follows is the module's own argv
        if not arg.startswith("-"):
            path = arg
            break
    return Invocation(interpreter=interp, is_posix_shell=base in POSIX_SHELLS,
                      payload_path=path or interp, code_args=tuple(code))


def _program_index(argv: list[str]) -> int:
    """Index of the real program — the first token that is not a wrapper, a wrapper's option, or a
    `VAR=value` assignment."""
    i = 0
    while i < len(argv):
        wrapper = _wrapper_name(argv[i])
        if wrapper is None:
            break
        value_opts = _WRAPPER_VALUE_OPTS.get(wrapper, frozenset())
        i += 1
        while i < len(argv):
            arg = argv[i]
            if arg in value_opts:
                i += 2
            elif (arg.startswith("-") and arg != "-") or _ASSIGNMENT.match(arg):
                i += 1
            else:
                break
    return i


def _wrapper_name(arg: str) -> str | None:
    """The wrapper this token names, or None. The basename must match EXACTLY and sit unqualified or
    in a system bin dir — otherwise a payload at `/tmp/.x/env.sh` or `/tmp/.x/command` is skipped as a
    wrapper and the scratch path it names is never checked."""
    name = os.path.basename(arg)
    if name not in _EXEC_WRAPPERS:
        return None
    parent = os.path.dirname(arg)
    return name if parent == "" or parent in _SYSTEM_BIN_DIRS else None


def _interpreter_base(arg: str) -> str:
    """`python3.11` → `python3`, `/usr/bin/node` → `node`. Version suffixes only: wrapper matching
    uses the exact basename, since `env.sh` is a payload and `env` is a wrapper."""
    return os.path.basename(arg).split(".")[0]


def _invocations(entry) -> list[Invocation]:
    """Every command line the entry executes, resolved. `argv` is only the FIRST — a unit's second
    `ExecStart=`, its `ExecStartPre/Post=`, `ExecReload=` or `ExecCondition=` each run their own, and a
    payload hides in one just as well (measured: five such forms went silent when only argv was read)."""
    argv = list(entry.argv or [])
    primary = " ".join(argv)
    # A parser with no command line to give falls back to the raw body; splitting that is 66ms of
    # meaningless work per entry, and the body is already matched as a part in its own right.
    return [resolve_invocation(argv)] + [
        resolve_invocation(_split_command(line))
        for line in entry.shell_lines if line != primary and line != entry.body]


def _split_command(line: str) -> list[str]:
    """A command line as argv, by the shell's own quoting rule — it is what strips the quotes around
    `sh -c '<payload>'`. An unbalanced quote falls back to whitespace rather than losing the line."""
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def _payload_path(entry) -> str | None:
    """The path of the code the entry RUNS — the script argument when an interpreter is argv[0], so a
    `node /path/daemon.js` autorun is read at daemon.js, not at the trusted `node`."""
    return resolve_invocation(entry.argv).payload_path


def launched_via_interpreter(entry) -> bool:
    """True when argv[0] is a script interpreter running a distinct script argument — so the payload
    script must be read for content-shape EVEN IF the interpreter is an attributed/trusted binary
    (its trust does not vouch for the arbitrary script it runs)."""
    return bool(entry.argv) and _payload_path(entry) not in (None, entry.argv[0])


# Derived from POSIX_SHELLS, never restated — the same five names in a third spelling is
# how the set drifts. `.dash` is not a real suffix, so suffixes stay explicit.
_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
_SHEBANG_SHELL = re.compile(rf"^#!.*\b(?:{'|'.join(POSIX_SHELLS)})\b")
_LEADING_NOISE = "﻿ \t\r\n"      # BOM is not whitespace, so lstrip() alone leaves it


def _runs_as_shell(entry, referenced: str) -> bool:
    """Whether the referenced payload is EXECUTED as a shell script. The resolver is authoritative —
    the payload cannot rename that away. Shebang and suffix are secondary, being author-chosen."""
    if resolve_invocation(entry.argv).is_posix_shell:
        return True
    payload = _payload_path(entry)
    if payload and payload.lower().endswith(_SHELL_SUFFIXES):
        return True
    return bool(_SHEBANG_SHELL.match(referenced.lstrip(_LEADING_NOISE)))


def _shell_context_text(entry, referenced: str) -> list[str]:
    """The shell command lines of an entry, each matched on its own so a path starting one is at a
    command position — joining them would anchor only the first.

    `shell_lines` is the parser's answer — every Exec* directive, continuations joined. The unit BODY
    is excluded: that is where a JS template literal or a comment lives (#1393)."""
    parts = list(entry.shell_lines) or [" ".join(entry.argv or [])]
    # A shell's code argument is a script in its own right, so each of ITS lines is a command
    # position. Taken from the resolver, never re-parsed out of the joined argv: a flag and a value
    # are indistinguishable once flattened, which is how `tar -c /tmp/x` became a foothold.
    for inv in _invocations(entry):
        if inv.is_posix_shell:
            parts += [line for arg in inv.code_args for line in arg.splitlines() if line.strip()]
    if referenced and _runs_as_shell(entry, referenced):
        parts.append(referenced)
    return parts


def _referenced_text(entry) -> str:
    """The content of the entry's referenced PAYLOAD (interpreter-aware, see `_payload_path`), capped,
    or '' — so the content-shape engines see the payload where it usually LIVES (a script the unit
    runs), not just the unit file or a trusted interpreter binary. FIFO-safe via pathsafe; a compiled
    binary simply won't match the (JS/shell-shaped) detectors."""
    payload = os.path.expanduser(_payload_path(entry) or "")
    if not os.path.isabs(payload):
        return ""                    # a bare name would resolve against saw's own working directory
    data = pathsafe.read_regular_bytes(Path(payload))
    if data is None:
        return ""
    return data[:_MAX_REFERENCED].decode("utf-8", "replace")

FOOTHOLD_ID = "autorun-unattributed-foothold"   # strong → ACTIVE_PERSISTENCE (rotation UNSAFE, exit 3)
REVIEW_ID = "autorun-new-unattributed"          # weak → info review item


@dataclass
class ContentSignal:
    hit: bool = False               # a decisive fetch/decode-exec shape (act-now regardless of owner)
    reasons: list[str] = field(default_factory=list)


def content_signal(entry, *, read_referenced: bool = False) -> ContentSignal:
    """Run the content-shape engines on the entry's command + body — and, when `read_referenced`
    (used for UNATTRIBUTED entries, where the referenced script is worth reading), on the referenced
    script's content too. `hit` is a decisive shape (act-now regardless of owner).

    #1335 — a malicious daemon that polls a legitimate endpoint (e.g. `api.github.com` every 60s) can't
    be caught by WHERE it connects; the discriminating features are BEHAVIOURAL, and for a script-based
    daemon they are STATIC: the poll interval is a literal in the code / the persistence artifact, and a
    persistence entry is non-interactive (no TTY, launchd/systemd-spawned) BY CONSTRUCTION. So we fuse,
    never blocklist a destination:
      * decisive `hit` — a fetch/decode-to-shell command, a decode→execute dropper, OR the dead-man
        self-destruct shape (#1334's corroborated `$HOME`-wipe) in the daemon's own code. The Mini
        Shai-Hulud wiper is plain code (poll → on token-revoke, delete `$HOME`), NOT a decode→exec
        dropper, so fusing `detect_destructive` here is what actually catches it.
      * corroborating reason — a short poll interval (the timer the dead-man loop runs on). Never
        decisive alone: benign software polls on a timer too (the FP guard is that escalation needs a
        decisive shape, and `detect_destructive` is itself corroborated home-root ∧ recursive ∧ delete,
        so firing it adds no new false positive)."""
    text = entry.shape_text()
    referenced = _referenced_text(entry) if read_referenced else ""
    if referenced:
        text += "\n" + referenced
    reasons: list[str] = []
    hit = False
    if mechanism._FETCH_PIPE_EXEC.search(text):
        reasons.append("fetch/decode-to-shell command")
        hit = True
    # Asked two ways: by PATH (immune to how the surrounding code reads) and, failing that, by
    # shell grammar over the lines that genuinely are a command line.
    payload = _payload_path(entry)
    if payload and mechanism._under_scratch(Path(payload)):
        reasons.append("runs code from a world-writable scratch directory")
        hit = True
    elif any(mechanism._SCRATCH_EXEC.search(line)
             for line in _shell_context_text(entry, referenced)):
        reasons.append("runs code from a world-writable scratch directory")
        hit = True
    if analyzer.detect_dropper(text):
        reasons.append("decode→execute dropper")
        hit = True
    if detect_destructive(text) is not None:
        reasons.append("dead-man self-destruct ($HOME wipe on an auth/token condition)")
        hit = True
    secs = _poll_seconds(entry.persistence)
    if secs is not None and 0 < secs <= 300:
        reasons.append(f"short poll interval ({secs}s)")
    return ContentSignal(hit=hit, reasons=reasons)


def _poll_seconds(persistence) -> int | None:
    """The daemon's poll/timer period in seconds, read STATICALLY from the persistence artifact —
    macOS `StartInterval` (`poll-interval=Ns`) or a systemd `OnUnitActiveSec` timer (`60`, `30s`,
    `1min`). This is the static analog of "interval regularity": a poll loop's cadence is a literal in
    the artifact, no live observation needed. None when no periodic timer is declared."""
    for pflag in persistence:
        if pflag.startswith("poll-interval="):
            try:
                return int(pflag.split("=", 1)[1].rstrip("s") or "0")
            except ValueError:
                return None
        if pflag.startswith("timer:OnUnitActiveSec="):
            return _systemd_seconds(pflag.split("=", 1)[1])
    return None


def _systemd_seconds(dur: str) -> int | None:
    """Parse a simple systemd time span (`60`, `30s`, `5min`, `1h`) to seconds — enough for the
    short-interval corroboration; an unrecognised/compound span returns None (no corroboration, never
    a crash)."""
    m = re.fullmatch(r"\s*(\d+)\s*(s|sec|secs|seconds|min|minutes|m|h|hours?)?\s*", dur)
    if not m:
        return None
    n, unit = int(m.group(1)), (m.group(2) or "s")
    mult = 60 if unit.startswith("m") and unit != "s" else 3600 if unit.startswith("h") else 1
    return n * mult


def correlate(entries, attributed: dict[str, bool]) -> set[str]:
    """Keys of UNATTRIBUTED entries whose referenced executable is shared by ≥2 entries — the
    multi-foothold campaign shape (a worm planting several re-run points at one payload). `attributed`
    maps entry-key → whether provenance attributed it."""
    execs = Counter()
    for e in entries:
        if e.exec_path and not attributed.get(e.key(), False):
            execs[os.path.normpath(os.path.expanduser(e.exec_path))] += 1
    shared = {p for p, n in execs.items() if n >= 2}
    return {e.key() for e in entries
            if e.exec_path and not attributed.get(e.key(), False)
            and os.path.normpath(os.path.expanduser(e.exec_path)) in shared}


def _where(entry, attrib) -> str:
    run = f"runs {entry.exec_path}" if entry.exec_path else "references no executable"
    tags = list(entry.persistence)
    if attrib.signed is False:
        tags.append("unsigned")
    if attrib.exec_class == "untrusted":
        tags.append("scratch/cache path")
    return f"{entry.path.name} ({run}" + (f"; {', '.join(tags)}" if tags else "") + ")"


def grade(entry, attrib, novel: str, shape: ContentSignal, correlated: bool) -> HygieneIssue | None:
    """Fuse the four signals for one entry into a graded HygieneIssue (or None = clean)."""
    is_new = novel in (NEW, CHANGED)
    unattributed = not attrib.attributed

    # STRONG foothold (→ warning, rotation UNSAFE): a decisive content shape (even a signed binary that
    # fetch-execs is act-now), OR an unattributed entry that is correlated across the surface, OR an
    # unattributed entry that both runs from a scratch/cache path AND re-executes (a persistence shape).
    strong = shape.hit or (unattributed and (correlated
             or (attrib.exec_class == "untrusted" and bool(entry.persistence))))
    if strong:
        why = list(shape.reasons)
        if correlated:
            why.append("shared payload across multiple autorun entries")
        detail = (f"An autorun entry re-executes code that is not attributable to a package, app, or "
                  f"signed binary — {_where(entry, attrib)}. " + (
                      "It " + "; ".join(why) + ". " if why else "")
                  + "A novel worm variant plants a foothold in a known location like this; being new "
                  "and unattributed is the signal, not a signature match.")
        return HygieneIssue(
            id=FOOTHOLD_ID, severity="warning",
            title="Unattributed autorun foothold (re-runs after the package is gone)",
            detail=detail,
            remediation="Verify you installed it; if not, treat the host as possibly compromised — "
                        f"disable/remove the entry, and {_WIPER_NOTE} (neutralize before rotating).")

    # REVIEW (→ info): something NEW and unattributed appeared since your last audit, without a decisive
    # bad shape. Requires trusted-baseline novelty, so a known benign-but-unattributed entry (e.g. your
    # own ~/bin tool) does not nag every run, and a first run stays quiet on this tier.
    if unattributed and is_new:
        verb = "appeared" if novel == NEW else "changed"
        return HygieneIssue(
            id=REVIEW_ID, severity="info",
            title="New unattributed autorun entry since your last audit",
            detail=f"An autorun entry {verb} that is not attributable to a package/app/signed binary — "
                   f"{_where(entry, attrib)}. New in itself is not proof of malware, but this is where "
                   "a novel foothold would appear; confirm you installed it.",
            remediation="If you set this up, it's fine. If not, inspect and remove it.")
    return None
