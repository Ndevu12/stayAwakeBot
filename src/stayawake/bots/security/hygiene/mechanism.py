#!/usr/bin/env python3
"""Mechanism-based persistence & backdoor sinks (wave-agnostic): ~/.ssh/authorized_keys, shell startup
files, and exec-on-every-git-command git config. Matches the MECHANISM (not a campaign's named IoC),
so a renamed variant — or a GhostApproval/SymJacking write-redirect into a user config file — is still
caught (#1161)."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .models import HygieneIssue, _WIPER_NOTE

#
# Where a worm — or a GhostApproval/SymJacking write-redirect that lands a payload in a
# user-owned config file — plants persistence that OUTLIVES the repo and any one campaign's
# named IoCs. The probes above match reported names (SHA1HULUD, gh-token-monitor); these match
# the MECHANISM, so a renamed variant is still caught. User-owned files carry legitimate content,
# so grading is signal-strength based (unambiguous backdoor shape → warning; review-worthy anomaly
# → info) rather than assert-malware. All read-only; absent paths/tools degrade to nothing.

# The shape a persistence line almost never has for a legitimate reason: a network fetch piped or
# eval'd into an interpreter, a decode-then-execute, or a script run out of a world-writable scratch
# dir. Reused across the shell-rc, SSH forced-command, and git-exec-config probes below. Benign tool
# init (`eval "$(rbenv init -)"`, `eval "$(brew shellenv)"`) contains no fetch, so it stays clean.
#
# A `… | X` SINK executes stdin as CODE only for a POSIX shell (always) or a scripting interpreter that
# is BARE — no program/module/script argument follows, so the fetched bytes ARE the program. `curl|bash`
# and `curl|python` (and `curl|python -`, stdin-as-script) fire; the FP pass proved `curl|python -m
# json.tool` (API pretty-print), `base64 -d|python3 -m json.tool` (JWT decode) and `diff <(curl a)
# <(curl b)` (proc-sub into a data consumer) are DATA, not exec — the bare-guard keeps them clean.
_FETCH = r"(?:curl|wget)"
_POSIX_SHELL = r"(?:sh|bash|zsh|dash|ksh)"
_SCRIPT_INTERP = r"(?:python[23]?|perl|ruby|node|php)"
_SCRATCH = r"(?:/tmp/|/var/tmp/|/dev/shm/|/private/tmp/)"
# stdin-as-code sink: POSIX shell (always), or a scripting interpreter with no program arg. A lone `-`
# (read the script from stdin) is still exec; `-m`/`-c`/`-e`/a script path make stdin DATA — the
# `(?!\s*(?:[\w/.]|-\S))` guard clears the latter while keeping bare `python` and `python -` flagged.
_PIPE_SINK = rf"(?:{_POSIX_SHELL}\b|{_SCRIPT_INTERP}\b(?!\s*(?:[\w/.]|-\S)))"
# a command that EXECUTES a file / proc-sub argument (shell, interpreter, or `source`). A bare `.`
# (dot-source) is handled by its OWN statement-boundary arm — elsewhere `.` is the current-dir ARGUMENT
# (`rsync -a . /tmp/bk`), so matching it after generic whitespace would false-positive.
_EXEC_CMD = rf"(?:{_POSIX_SHELL}|{_SCRIPT_INTERP}|source)"
# exec wrappers preceding the real executable, so a scratch payload run via one still flags.
_EXEC_WRAP = r"(?:env|sudo|nohup|nice|setsid|exec|command|stdbuf|time)"
# Runs are BOUNDED + POSSESSIVE ({0,512}+ where the class excludes the delimiter `|`), never `*`: an
# unbounded/backtracking run scans-and-retries toward EOL at EVERY curl/base64 anchor — with a token
# every few chars that is a too-large linear constant that straddles the ReDoS-guard budget (#1156,
# found round-3). The possessive `+` kills the per-anchor backtrack; the eval arm (whose class can't
# exclude its `$(` delimiter) is bounded tight at {0,256} instead. A real fetch→pipe one-liner is far
# under 512, so detection is identical — and bounding the QUANTIFIER (not truncating the input, a
# pad-past-it evasion boundary, #1156) keeps it evasion-safe.
_FETCH_PIPE_EXEC = re.compile(
    rf"\b{_FETCH}\b[^\n|]{{0,512}}+\|\s*{_PIPE_SINK}"                              # curl … | bash / | python[-]
    rf"|\beval\b[^\n]{{0,256}}\$\(\s*{_FETCH}\b"                                   # eval "$(curl …)"
    rf"|(?:^|[;&|]|\s){_EXEC_CMD}\b\s+<\(\s*{_FETCH}\b"                            # bash <(curl …)
    rf"|(?:^|[;&|])\s*\.\s+<\(\s*{_FETCH}\b"                                       # . <(curl …)   (stmt boundary)
    rf"|\bbase64\s+(?:-d|-D|--decode)\b[^\n|]{{0,512}}+\|\s*{_PIPE_SINK}"           # … | base64 -d | sh
    rf"|(?:^|[;&|]|\s){_EXEC_CMD}\b\s+[\"']?{_SCRATCH}"                            # bash /tmp/x ; source /tmp/x
    rf"|(?:^|[;&|])\s*\.\s+[\"']?{_SCRATCH}"                                       # . /tmp/x      (stmt boundary)
    rf"|(?:^|[;&|`]|&&|\|\||\$\()\s*(?:{_EXEC_WRAP}\s+){{0,4}}(?:\w+=\S*\s+){{0,6}}[\"']?{_SCRATCH}",  # ; /tmp/x ; env X=1 /tmp/x
    re.IGNORECASE)

# Forced-command on an authorized_keys line: `command="…" ssh-ed25519 …`. Scanned across the WHOLE line
# (fail-closed): parsing only the option field (before the key type) would SILENTLY DROP a backdoor on
# an unrecognized key type (`ssh-*-cert-v01@openssh.com`) or one whose command value contains a key-type
# substring (a self-propagating worm re-adding its own key). The rare cost is a `command="…"` written in
# the trailing free-text COMMENT being read as a forced command — at worst an info-level restricted-key
# note (a benign comment carries no real fetch/scratch payload, so it never reaches a warning).
_FORCED_COMMAND = re.compile(r'\bcommand="((?:[^"\\]|\\.)*)"')

_SSH_AUTHKEYS = ("authorized_keys", "authorized_keys2")

# World-writable scratch roots. A path is treated as "under scratch" only at a real path boundary
# (equals a root or is a descendant) — NOT an unanchored substring, so a private `/opt/acme/tmp/hooks`
# or a `command="rrsync … /var/tmp/repo"` DATA path is not mistaken for the system scratch dir.
_SCRATCH_ROOTS = (Path("/tmp"), Path("/var/tmp"), Path("/private/tmp"), Path("/dev/shm"))


def _other_writable(p: Path) -> bool:
    """True if `p` is writable by 'other' (world). Group-write is deliberately NOT flagged: on
    distros with per-user private groups (umask 002) a benign file is group-writable by the user's
    own group — flagging it would be a false positive. World-write is unambiguous."""
    try:
        return bool(p.stat().st_mode & 0o002)
    except (OSError, ValueError):     # ValueError: an embedded-NUL path (mirror _under_scratch)
        return False


def _under_scratch(p: Path) -> bool:
    """True if `p` resolves (textually — no symlink follow / existence needed) to a world-writable
    scratch dir or a descendant of one, at a path boundary. Used for the SSH forced-command executable
    and git core.hooksPath/fsmonitor, where a scratch *executable* is the backdoor signal (a scratch
    path passed only as a data argument is not)."""
    try:
        norm = Path(os.path.normpath(os.path.expanduser(str(p))))
    except (OSError, ValueError):
        return False
    return any(norm == root or root in norm.parents for root in _SCRATCH_ROOTS)


def check_ssh_authorized_keys() -> list[HygieneIssue]:
    """Inspect ~/.ssh/authorized_keys — the SSH-persistence sink GhostApproval/SymJacking writes
    to (an attacker's key granting durable access, T1098.004). User-owned, so signal-graded:
    world-writable perms or a fetch/decode/scratch forced-command → warning; a plain restricted-key
    entry → info to eyeball. We cannot know which keys are yours, so a bare extra key is not
    asserted malicious — but the shapes that ARE unambiguous are surfaced."""
    issues: list[HygieneIssue] = []
    ssh_dir = Path.home() / ".ssh"
    if _other_writable(ssh_dir):
        issues.append(HygieneIssue(
            id="ssh-dir-writable",
            severity="warning",
            title="~/.ssh is world-writable",
            detail=f"{ssh_dir} is writable by other users — anyone on the host (or a redirected "
                   "write) can drop an authorized_keys that grants SSH access.",
            remediation="Restrict it: chmod 700 ~/.ssh.",
        ))
    for name in _SSH_AUTHKEYS:
        keyfile = ssh_dir / name
        try:
            if not keyfile.is_file():
                continue
        except OSError:
            continue
        if _other_writable(keyfile):
            issues.append(HygieneIssue(
                id="ssh-authorized-keys-writable",
                severity="warning",
                title=f"~/.ssh/{name} is world-writable",
                detail=f"{keyfile} can be appended by any user on the host — an attacker can add a "
                       "key for persistent SSH access without touching your account.",
                remediation=f"Restrict it: chmod 600 {keyfile}.",
            ))
        try:
            text = keyfile.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        malicious, restricted = [], 0
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = _FORCED_COMMAND.search(line)     # whole line — fail closed (see _FORCED_COMMAND note)
            if m is None:
                continue
            cmd = m.group(1)
            argv = cmd.split()
            # backdoor = a fetch/decode/scratch-EXEC shape (incl. via a wrapper or after a `;`/`&&`), or
            # the forced executable itself in a scratch dir. A scratch path used only as a data argument
            # (`rrsync … /var/tmp/repo`) is NOT — _FETCH_PIPE_EXEC and the argv[0] check distinguish them.
            if _FETCH_PIPE_EXEC.search(cmd) or (argv and _under_scratch(Path(argv[0]))):
                malicious.append(cmd[:120])
            else:
                restricted += 1
        if malicious:
            issues.append(HygieneIssue(
                id="ssh-authorized-keys-forced-command",
                severity="warning",
                title=f"Backdoor forced-command in ~/.ssh/{name}",
                detail="An authorized_keys entry forces a suspicious command on connect: "
                       + "; ".join(malicious[:3]) + ". A key that runs a fetch/decode/scratch-dir "
                       "command on login is a classic SSH persistence backdoor (T1098.004).",
                remediation="Remove the entry if you did not add it, and treat the host as possibly "
                            f"compromised — {_WIPER_NOTE} (neutralize before rotating any credential).",
            ))
        elif restricted:
            issues.append(HygieneIssue(
                id="ssh-authorized-keys-restricted",
                severity="info",
                title=f"Restricted (forced-command) key in ~/.ssh/{name}",
                detail=f"{keyfile} has {restricted} key(s) with a forced command / restrictive "
                       "options. Legitimate for rsync/borg/git-shell keys — verify you added them.",
                remediation="If unfamiliar, remove the entry and rotate that key.",
            ))
    return issues


# Shell startup files sourced on every interactive/login shell — a fetch-to-shell line here runs
# on each new terminal (T1546.004). Covers bash/zsh/sh + fish; a symlinked dotfile is followed
# (read_text) since it's the user's own config.
_SHELL_RC_FILES = (".bashrc", ".bash_profile", ".bash_login", ".profile",
                   ".zshrc", ".zprofile", ".zshenv", ".zlogin")


def _iter_shell_rc() -> list[Path]:
    home = Path.home()
    found: list[Path] = []
    for name in (*_SHELL_RC_FILES, ".config/fish/config.fish"):
        p = home / name
        try:
            if p.is_file():
                found.append(p)
        except OSError:
            continue
    return found


def check_shell_profile() -> list[HygieneIssue]:
    """Flag a network-fetch-to-shell / decode-exec / scratch-dir-exec line planted in a shell
    startup file — a wave-agnostic persistence backdoor that runs on every new shell. Benign tool
    init (rbenv/pyenv/direnv/brew) does not fetch-and-run, so it stays clean."""
    issues: list[HygieneIssue] = []
    for path in _iter_shell_rc():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        hits = []
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if _FETCH_PIPE_EXEC.search(line):
                hits.append(f"line {lineno}: {line[:120]}")
        if hits:
            issues.append(HygieneIssue(
                id="shell-profile-fetch-exec",
                severity="warning",
                title=f"Fetch-to-shell backdoor in {path.name}",
                detail=f"{path} runs a network-fetch-piped-to-shell / decode-exec line on every "
                       "shell — " + "; ".join(hits[:5]) + ". A legitimate startup file does not "
                       "download-and-execute code (T1546.004).",
                remediation="Open the file, remove the offending line(s), and treat the host as "
                            f"possibly compromised — {_WIPER_NOTE} (neutralize before rotating).",
            ))
    return issues


# git config keys whose VALUE git executes (hooks, monitors, pagers, filters, !-aliases). Flag only
# when the value has a fetch/decode/scratch backdoor shape — `core.pager=less` is fine,
# `core.pager=!curl …|sh` is not. core.fsmonitor and core.hooksPath get dedicated, stronger rules.
_GIT_EXEC_KEY = re.compile(
    r"^(?:core\.(?:editor|pager|sshcommand|askpass)"
    r"|sequence\.editor|alias\.[^=]+|filter\.[^=]+\.(?:clean|smudge|process)"
    # credential.(?:<url>.)?helper — a per-URL helper execs too, so the sub-key variant can't slip
    r"|diff\.(?:external|[^=]+\.command)|merge\.[^=]+\.driver|credential\.(?:[^=]+\.)?helper)$")

# git's full boolean vocabulary — core.fsmonitor set to any of these selects the builtin monitor (or
# disables it), NOT an external command, so it is benign. Only a non-boolean VALUE is a run-a-command.
_GIT_BOOL = {"true", "false", "yes", "no", "on", "off", "1", "0"}

# keys where git treats a leading `!` as a shell command (aliases, credential.helper) — the sigil is
# stripped before matching so a no-space `!bash /tmp/x` reaches the scratch-exec arms.
_GIT_BANG_KEY = re.compile(r"^(?:alias\.[^=]+|credential\.(?:[^=]+\.)?helper)$")


def _git_global_config() -> list[tuple[str, str]]:
    """(key, value) pairs from the GLOBAL git config only (never a scanned repo's local config).
    Git-absent / no config → []. Uses -z framing so a multi-line value can't desync the parse."""
    try:
        # errors="replace": a config VALUE with a non-locale-decodable byte must not crash the audit
        # (text=True decodes strict by default → UnicodeDecodeError) — that would be an evasion vector
        # (plant the malicious config + one bad byte to hang the auditor). Mirrors read_text(errors=…).
        r = subprocess.run(["git", "config", "--global", "--list", "-z"],
                           capture_output=True, text=True, errors="replace", timeout=10)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return []
    if r.returncode != 0:
        return []
    pairs: list[tuple[str, str]] = []
    for chunk in r.stdout.split("\0"):
        if not chunk:
            continue
        key, _, value = chunk.partition("\n")      # `git config -z` = key\nvalue per record
        pairs.append((key.lower(), value))
    return pairs


def check_git_config_execution() -> list[HygieneIssue]:
    """Flag a GLOBAL git config that makes git execute an attacker command on ordinary operations:
    a non-boolean core.fsmonitor (runs every git op), a core.hooksPath under a world-writable or
    scratch dir, or any exec-capable key whose value fetch/decode-execs. Repo-borne `.git/config`
    RCE is the scan-side complement, deliberately out of scope here (host hygiene = global config)."""
    issues: list[HygieneIssue] = []
    for key, value in _git_global_config():
        val = value.strip()
        if not val:
            continue
        if key == "core.fsmonitor":
            if val.lower() in _GIT_BOOL:
                continue                       # builtin FSMonitor toggle — benign
            argv = val.split()
            if _FETCH_PIPE_EXEC.search(val) or (argv and _under_scratch(Path(os.path.expanduser(argv[0])))):
                issues.append(HygieneIssue(
                    id="git-fsmonitor-command",
                    severity="warning",
                    title="git core.fsmonitor runs a suspicious command on every operation",
                    detail=f"Global git config sets core.fsmonitor = {val[:120]} — git runs this on "
                           "every repository operation (T1546), and it fetch/decode-execs or runs from "
                           "a world-writable scratch dir — an exec-on-every-git-command persistence hook.",
                    remediation="Unset it: git config --global --unset core.fsmonitor.",
                ))
            else:
                issues.append(HygieneIssue(
                    id="git-fsmonitor-external",
                    severity="info",
                    title="git core.fsmonitor runs an external file-system monitor",
                    detail=f"Global git config sets core.fsmonitor = {val[:120]} — git runs this on "
                           "every operation. Legitimate for a large-monorepo monitor (Watchman / "
                           "rs-git-fsmonitor); verify you installed it.",
                    remediation="If unfamiliar, unset it: git config --global --unset core.fsmonitor.",
                ))
        elif key == "core.hookspath":
            hook_dir = Path(os.path.expanduser(val))
            if _other_writable(hook_dir) or _under_scratch(hook_dir):
                issues.append(HygieneIssue(
                    id="git-hookspath-unsafe",
                    severity="warning",
                    title="git core.hooksPath points at an unsafe directory",
                    detail=f"Global core.hooksPath = {val[:120]} is world-writable or under a "
                           "scratch dir — any git operation runs hooks an attacker can plant (T1546).",
                    remediation="Point core.hooksPath at a directory only you can write, or unset it.",
                ))
            else:
                issues.append(HygieneIssue(
                    id="git-hookspath-set",
                    severity="info",
                    title="git core.hooksPath is set globally",
                    detail=f"Global core.hooksPath = {val[:120]} — every repo runs hooks from here. "
                           "Verify it's a directory you control.",
                    remediation="If unfamiliar, unset it: git config --global --unset core.hooksPath.",
                ))
        elif _GIT_EXEC_KEY.match(key):
            # git runs an alias / credential.helper value prefixed with `!` as a shell command. Strip
            # that sigil before matching so a no-space `!bash /tmp/x` / `!/tmp/evil.sh` reaches the
            # scratch-exec arms (which anchor on a statement boundary, not `!`) — a git quirk kept out
            # of the shared SSH/shell-rc regex. Non-`!` keys (pager/editor/filter) match val directly.
            probe = re.sub(r"^\s*!\s*", "", val) if _GIT_BANG_KEY.match(key) else val
            if _FETCH_PIPE_EXEC.search(probe):
                issues.append(HygieneIssue(
                    id="git-config-fetch-exec",
                    severity="warning",
                    title=f"git {key} runs a fetch-to-shell command",
                    detail=f"Global git config sets {key} = {val[:120]} — git executes this value and "
                           "it fetches/decodes-and-runs code or runs from a scratch dir (T1546).",
                    remediation=f"Remove it: git config --global --unset {key} (or fix the alias). "
                                "Treat the host as possibly compromised if you did not set it.",
                ))
    return issues


