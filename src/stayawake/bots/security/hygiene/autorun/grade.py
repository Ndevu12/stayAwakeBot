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


# Inline-code flags PER INTERPRETER, because they conflict: `-m` names a module for python but is job
# control for a shell, and `-c` is an archive for tar and a config file for redis. The code is IN argv
# (already seen via `shape_text()`), so its argument must never be mistaken for a path to read.
_CODE_FLAGS = {
    **{shell: frozenset({"-c"}) for shell in POSIX_SHELLS},
    "python": frozenset({"-c"}), "python2": frozenset({"-c"}), "python3": frozenset({"-c"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "nodejs": frozenset({"-e", "--eval", "-p", "--print"}),
    "deno": frozenset({"-e", "--eval"}), "bun": frozenset({"-e", "--eval"}),
    "ruby": frozenset({"-e"}), "perl": frozenset({"-e", "-E"}), "php": frozenset({"-r"}),
    "osascript": frozenset({"-e"}),
}
_MODULE_FLAGS = {"python": frozenset({"-m"}), "python2": frozenset({"-m"}),
                 "python3": frozenset({"-m"})}

# A shell's `-c` flag, including the clustered short forms a shell accepts (`bash -lc`, `sh -ic`).
# `-c` must end the cluster, since it consumes the next argument.
_SHELL_C_FLAG = re.compile(r"-[A-Za-z]{0,4}c")
# Shell options that consume the next token, so `bash --rcfile /etc/x -c …` still resolves.
_SHELL_VALUE_OPTS = frozenset({"-o", "+o", "--rcfile", "--init-file"})

# Programs whose `-c` argument is a shell command. Wider than POSIX_SHELLS, which names the grammar:
# `ash` IS /bin/sh on Alpine and BusyBox, `mksh` ships as /bin/sh on Android and in Debian, and
# `tcsh`/`fish` are not POSIX but their `-c` is still a command. `$SHELL` is how a LaunchAgent asks
# for the login shell without naming it. All nine were caught by merged main and lost by anchoring on
# a five-name literal.
_C_FLAG_SHELLS = frozenset(POSIX_SHELLS) | {
    "ash", "busybox", "mksh", "pdksh", "yash", "rbash", "bash5", "sh5", "tcsh", "csh", "fish",
    "$SHELL", "${SHELL}"}

# Programs whose OWN `-c` carries a shell command string — they exec a shell themselves, so their
# operand sits between the program and the flag and the owner test cannot see it.
_SHELL_COMMAND_CARRIERS = frozenset({"su", "runuser", "script", "flock"})

# Programs that execute the command in ANOTHER root, container or host. A `/tmp` path there is not a
# foothold on THIS machine, and `autorun-unattributed-foothold` means a live foothold on this one.
# A DENYLIST is the right polarity: the host-level prefix families are open-ended (49 measured —
# su/runuser/chrt/taskset/systemd-run/strace/caffeinate/direnv/poetry/…, and more exist), so an
# allowlist of them carries an unbounded false-negative surface. This list is ~10 deliberate names.
_BOUNDARY_PROGRAMS = frozenset({"docker", "podman", "nerdctl", "kubectl", "lxc", "machinectl",
                                "distrobox-enter", "chroot", "flatpak", "ssh"})

# Exec wrappers stand BEFORE the real program (`env A=1 bash -c …`, `sudo -u x node app.js`). Used
# ONLY to find which file an entry runs — never to decide whether a code argument is shell.
_EXEC_WRAPPERS = frozenset({"env", "sudo", "nohup", "nice", "setsid", "exec", "command", "stdbuf",
                            "time", "doas"})
# Wrapper options that consume the NEXT token. Per wrapper because they conflict: `stdbuf -i` takes a
# value, `env -i` does not.
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


def shell_code_args(argv) -> tuple[str, ...]:
    """The arguments of a command line that are SHELL code.

    Decided AT THE FLAG — the token that owns `-c` — never by resolving the program. `tar -c
    /tmp/staging` and `sudo -u nobody /bin/sh -c /tmp/x` differ only in that token, and every attempt
    to answer it by walking the prefix went silent on some real path: NixOS `/run/wrappers/bin/sudo`,
    linuxbrew, `/usr/local/sbin`, and 49 measured prefix families (`su`, `chrt`, `systemd-run`,
    `caffeinate`, `direnv`, `poetry run`, …). Anchoring on the shell needs none of them enumerated."""
    argv = list(argv or [])
    if _crosses_a_boundary(argv):
        return ()
    code: list[str] = []
    for n, arg in enumerate(argv[:-1]):
        if n == 0 or not _SHELL_C_FLAG.fullmatch(arg):
            continue
        if _shell_owns_the_flag(argv, n) or any(
                _interpreter_base(a) in _SHELL_COMMAND_CARRIERS for a in argv[:n]):
            code.append(argv[n + 1])
    # `env -S "bash -c '<payload>'"` packs a whole command line into one argument.
    for n, arg in enumerate(argv[:-1]):
        if arg in ("-S", "--split-string") and _interpreter_base(argv[n - 1]) == "env":
            code.extend(shell_code_args(_split_command(argv[n + 1])))
    return tuple(code)


def _shell_owns_the_flag(argv: list[str], flag: int) -> bool:
    """Whether the program owning the `-c` at `flag` is a shell, looking back past the shell's OWN
    options. Reading only the token before the flag meant one option token turned the check off:
    `bash -lc` resolved but `bash -l -c` did not, and `bash -l -c` is the ordinary way a LaunchAgent
    asks for a login environment."""
    i = flag - 1
    while i >= 0:
        if _interpreter_base(argv[i]) in _C_FLAG_SHELLS or argv[i] in _C_FLAG_SHELLS:
            return True
        if argv[i].startswith("-") or argv[i].startswith("+"):
            i -= 1
        elif i > 0 and argv[i - 1] in _SHELL_VALUE_OPTS:
            i -= 2
        else:
            return False
    return False


def _crosses_a_boundary(argv: list[str]) -> bool:
    """Whether this command line executes somewhere other than this host.

    Only the PROGRAM counts, and only where a real one lives. Matching any token let one decoy
    argument switch the detector off — `sh -c <payload> docker` went silent — and matching any path
    let a payload named `/tmp/.x/docker` do the same. An entry has to run, so a worm cannot put a
    boundary program in the program position without actually launching it."""
    if not argv:
        return False
    program = argv[min(_program_index(argv), len(argv) - 1)]
    if os.path.basename(program) not in _BOUNDARY_PROGRAMS:
        return False
    parent = os.path.dirname(program)
    return parent == "" or parent in _SYSTEM_BIN_DIRS


def resolve_invocation(argv) -> Invocation:
    """Resolve ONE command line — which file it runs. Per command line, never per entry: `entry.argv`
    is only the first of them, and `_invocations` covers the rest.

    Every field is a POSITIVE identification or absent. A walk that loses the line returns no payload
    rather than a guess: guessing resolved `su -c '<payload>' user` to the command STRING as a path,
    which matched the scratch check by luck and handed an invented path to the file reader."""
    argv = list(argv or [])
    if not argv:
        return Invocation()
    i = _program_index(argv)
    if i >= len(argv) or argv[i].startswith("-"):
        return Invocation()                    # the walk lost the line — say so, do not invent
    interp, rest = argv[i], argv[i + 1:]
    base = _interpreter_base(interp)
    if base not in _INTERPRETERS:
        return Invocation(interpreter=interp, payload_path=interp)
    code_flags = _CODE_FLAGS.get(base, frozenset())
    module_flags = _MODULE_FLAGS.get(base, frozenset())
    code, path = [], None
    for n, arg in enumerate(rest):
        if arg in code_flags or (base in POSIX_SHELLS and _SHELL_C_FLAG.fullmatch(arg)):
            if n + 1 < len(rest):
                code.append(rest[n + 1])
            break              # what follows the code is an argument TO it ($0, $@) — never a path
        if arg in module_flags:
            break              # a module NAME, and what follows is the module's own argv
        if not arg.startswith("-"):
            path = arg
            break
    # No script argument means there is no file this runs: the code is inline, or it names a module.
    # Reporting the interpreter would send the reader 133 KB of `/bin/sh` to content-scan.
    return Invocation(interpreter=interp, is_posix_shell=base in POSIX_SHELLS,
                      payload_path=path, code_args=tuple(code))


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


def _command_argvs(entry) -> list[list[str]]:
    """Every command line the entry executes, as argv. `entry.argv` is only the FIRST — a unit's
    second `ExecStart=`, its `ExecStartPre/Post=`, `ExecReload=` or `ExecCondition=` each run their
    own, and a payload hides in one just as well (five such forms went silent when only argv was
    read). A parser with no command line to give falls back to the raw body; splitting that is 66ms
    per entry for nothing, and the body is already matched as a part in its own right."""
    argv = list(entry.argv or [])
    # Re-split a line ONLY when the parser says its argv is inexact. systemd's ExecStart argv is a
    # naive `.split()`, so `sh -c 'exec /tmp/x'` truncates at the space and rejoins to the identical
    # string — a text comparison could never spot it. A plist's argv is a real array, and re-splitting
    # its own join instead destroyed the quoting of a multi-line argument.
    lines = [] if entry.argv_is_exact else [_split_command(ln) for ln in entry.shell_lines
                                            if ln != entry.body]
    seen, out = set(), []
    for candidate in ([argv] + lines if argv else lines or [_split_command(entry.body)]):
        key = tuple(candidate)
        if candidate and key not in seen:
            seen.add(key)
            out.append(candidate)
    return out


_HEREDOC_START = re.compile(r"<<-?\s{0,8}(\\?)([\"']?)([A-Za-z_]\w{0,63})\2")
# Keywords that introduce a command: `while true; do PAYLOAD` is a command position, and it is the
# canonical poll-beacon shape (#1335). `eval` is here because its argument is a command too.
_OPENS_A_COMMAND = frozenset({"do", "then", "else", "elif", "eval", "{", "(", "!", "time"})
_CASE_OPENS = re.compile(r"(?:^|\s)case\s[^;&|]{0,256}\sin$")
_MAX_SCRIPT = 64 * 1024
_MAX_SUBSTITUTION_DEPTH = 8


def shell_command_lines(script: str, _depth: int = 0) -> list[str]:
    """The COMMAND POSITIONS of a shell script — the text following each separator that actually
    separates commands, which is the only text where a leading path means execution.

    This has to track quoting, because the difference between a command and a datum is entirely
    quote state. Splitting on newlines and special-casing continuations, heredocs and `case` labels
    was measured wrong seven ways: a multi-line quoted string, `<<\\EOF`, a `$(…)` spanning lines, a
    bash array, a delimiter recurring inside its own body, two heredocs opened on one line, and CRLF
    each turned a data line into a fabricated command position — reaching exit 3 on signed agents.
    A `case` label is skipped for the same reason, and `while true; do <payload>` is NOT skipped."""
    out: list[str] = []
    text, i, n = script[:_MAX_SCRIPT], 0, len(script[:_MAX_SCRIPT])
    start, depth, quote, pending_heredocs = 0, 0, "", []
    in_case = in_pattern = False
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "\\":
            i += 2
            continue
        if ch in "'\"":
            quote, i = ch, i + 1
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t\n;&|"):
            i = text.find("\n", i)
            if i < 0:
                break
            continue
        found = _HEREDOC_START.match(text, i)
        if found:
            pending_heredocs.append(found.group(3))
            i = found.end()
            continue
        if ch == "\n" and pending_heredocs:
            i = _skip_heredoc_bodies(text, i + 1, pending_heredocs)
            start = i
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            if depth:
                depth -= 1
            elif ch == ")":                       # a `case` label at depth 0 — a pattern, not a command
                start, in_pattern = i + 1, False
        # Inside a `case` label the `|` joins PATTERNS, so `/tmp/*|/var/tmp/*)` is one datum: a backup
        # agent skipping scratch dirs reached "isolate and rebuild" when it was read as a pipe.
        separator = "\n;&" if in_pattern else "\n;&|"
        if ch == "|" and text[:i].rstrip()[-1:] == ">":
            separator = "\n;&"                    # `>| file` is a zsh clobber redirect, not a pipe
        if depth == 0 and (ch in separator or (ch == "{" and text[i:i + 2] != "{{")):
            chunk = text[start:i]
            _emit(out, chunk, _depth)
            if _CASE_OPENS.search(chunk):
                in_case = True
            elif in_case and chunk.strip() == "esac":
                in_case = False
            if in_case and (_CASE_OPENS.search(chunk) or text[i:i + 2] == ";;"):
                in_pattern = True
            start = i + 1
        i += 1
    _emit(out, text[start:], _depth)
    return out


def _emit(out: list[str], chunk: str, depth: int = 0) -> None:
    """Record a command position, past any assignment prefix and any keyword that merely introduces
    one. `FOO=bar /tmp/payload` runs the payload; `FOO=( /tmp/x )` and `FOO="…/tmp/x…"` only NAME it,
    and reading their value as a command is what flagged an rsync exclude list and a bash array."""
    chunk = chunk.strip().lstrip("&|;")
    # `OUT=`/tmp/x`` assigns, but the substitution still RUNS — so its body is a command position of
    # its own, and dropping it with the assignment lost a real foothold.
    # Bounded: `$(` nested 2,000 deep hit Python's recursion limit and CRASHED the audit, which an
    # attacker can put in their own payload to be scanned silently instead of reported. Real shell
    # does not nest substitutions past two or three.
    for body in _substitutions(chunk) if depth < _MAX_SUBSTITUTION_DEPTH else ():
        if body.strip() and body != chunk:
            out.extend(shell_command_lines(body, depth + 1))
    piece = _strip_assignments(chunk)
    while piece:
        out.append(piece)
        head, _, rest = piece.partition(" ")
        if head not in _OPENS_A_COMMAND or not rest.strip():
            return
        piece = _strip_assignments(rest.strip())


def _substitutions(text: str) -> list[str]:
    """The bodies of `$(…)` and backtick command substitutions in `text` — each one executes."""
    bodies, i = [], 0
    while i < len(text):
        if text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += (text[j] == "(") - (text[j] == ")")
                j += 1
            bodies.append(text[i + 2:j - 1])
            i = j
        elif text[i] == "`":
            j = text.find("`", i + 1)
            if j < 0:
                break
            bodies.append(text[i + 1:j])
            i = j + 1
        else:
            i += 1
    return bodies


def _strip_assignments(piece: str) -> str:
    """`piece` with any leading `NAME=value` assignments removed — '' when that is all it was."""
    while (found := _ASSIGNMENT.match(piece)):
        i, depth, quote = found.end(), 0, ""
        while i < len(piece):                      # the value ends at unquoted, unnested whitespace
            ch = piece[i]
            if quote:
                quote = "" if ch == quote else quote
            elif ch in "'\"":
                quote = ch
            elif ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif ch.isspace() and depth <= 0:
                break
            i += 1
        piece = piece[i:].strip()
    return piece


def _skip_heredoc_bodies(text: str, i: int, delimiters: list[str]) -> int:
    """Past the bodies of every heredoc opened on the line just ended. Their content is DATA — a
    line of it beginning with a scratch path is not a command."""
    while delimiters:
        end = text.find("\n", i)
        line = text[i:] if end < 0 else text[i:end]
        if line.strip() == delimiters[0]:
            delimiters.pop(0)
        if end < 0:
            return len(text)
        i = end + 1
    return i


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
    # A shell's code argument is a script in its own right, so each of its command lines is a command
    # position. It is EXCISED from the joined line rather than left in both: flattened, the script has
    # no command positions at all, so `case $d in /tmp/*|/var/tmp/*)` read its pattern alternation as
    # a pipe and called an ordinary backup agent a foothold.
    parts, seen_code = [], []
    for line_argv in _command_argvs(entry):
        code_args = shell_code_args(line_argv)
        seen_code += code_args
        for code in code_args:
            parts += shell_command_lines(code)
    for line in entry.shell_lines or [" ".join(entry.argv or [])]:
        for code in seen_code:
            line = line.replace(code, " ")
        parts.append(line)
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
