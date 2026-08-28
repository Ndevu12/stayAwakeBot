#!/usr/bin/env python3
"""Mechanism-based persistence & backdoor sinks (wave-agnostic): ~/.ssh/authorized_keys, shell startup
files, and exec-on-every-git-command git config. Matches the MECHANISM (not a campaign's named IoC),
so a renamed variant — or a GhostApproval/SymJacking write-redirect into a user config file — is still
caught."""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from .models import HygieneIssue, POSIX_SHELLS, SCRATCH_ROOTS, _WIPER_NOTE

#
# Where a worm — or a GhostApproval/SymJacking write-redirect that lands a payload in a
# user-owned config file — plants persistence that OUTLIVES the repo and any one campaign's
# named IoCs. The probes above match reported names (SHA1HULUD, gh-token-monitor); these match
# the MECHANISM, so a renamed variant is still caught. User-owned files carry legitimate content,
# so grading is signal-strength based (unambiguous backdoor shape → warning; review-worthy anomaly
# → info) rather than assert-malware. All read-only; absent paths/tools degrade to nothing.

_FETCH = r"(?:curl|wget)"
_POSIX_SHELL = rf"(?:{'|'.join(POSIX_SHELLS)})"
_SCRIPT_INTERP = r"(?:python[23]?|perl|ruby|node|php)"
_SCRATCH = rf"(?:{'|'.join(root + '/' for root in SCRATCH_ROOTS)})"
_PIPE_SINK = rf"(?:{_POSIX_SHELL}\b|{_SCRIPT_INTERP}\b(?!\s*(?:[\w/.]|-\S)))"
_EXEC_CMD = rf"(?:{_POSIX_SHELL}|{_SCRIPT_INTERP}|source)"
_EXEC_WRAP = r"(?:env|sudo|nohup|nice|setsid|exec|command|stdbuf|time)"
_FETCH_PIPE_EXEC = re.compile(
    rf"\b{_FETCH}\b[^\n|]{{0,512}}+\|\s*{_PIPE_SINK}"                              # curl … | bash / | python[-]
    rf"|\beval\b[^\n]{{0,256}}\$\(\s*{_FETCH}\b"                                   # eval "$(curl …)"
    rf"|(?:^|[;&|]|\s){_EXEC_CMD}\b\s+<\(\s*{_FETCH}\b"                            # bash <(curl …)
    rf"|(?:^|[;&|])\s*\.\s+<\(\s*{_FETCH}\b"                                       # . <(curl …)   (stmt boundary)
    rf"|\bbase64\s+(?:-d|-D|--decode)\b[^\n|]{{0,512}}+\|\s*{_PIPE_SINK}"           # … | base64 -d | sh
    rf"|(?:^|[;&|]|\s){_EXEC_CMD}\b\s+[\"']?{_SCRATCH}",                           # bash /tmp/x ; source /tmp/x
    re.IGNORECASE)

_SCRATCH_EXEC = re.compile(
    rf"(?:^|[;&|])\s*\.\s+[\"']?{_SCRATCH}"                                        # . /tmp/x      (stmt boundary)
    # `(?<!>)` on the pipe: zsh's clobber redirect `>|` is a WRITE, not a pipe, so `pwd >| /tmp/f`
    # is not execution. Without it every shell that emits one flags itself.
    rf"|(?:^|[;&`]|(?<!>)\||&&|\|\||\$\()\s*(?:{_EXEC_WRAP}\s+){{0,4}}(?:\w+=\S*\s+){{0,6}}[\"']?{_SCRATCH}",
    re.IGNORECASE)

_FORCED_COMMAND = re.compile(r'\bcommand="((?:[^"\\]|\\.)*)"')

_SSH_AUTHKEYS = ("authorized_keys", "authorized_keys2")

_SCRATCH_PATHS = tuple(Path(root) for root in SCRATCH_ROOTS)


def _other_writable(p: Path) -> bool:
    """True if `p` is writable by 'other' (world).  World-write is unambiguous."""
    try:
        return bool(p.stat().st_mode & 0o002)
    except (OSError, ValueError):     # ValueError: an embedded-NUL path (mirror _under_scratch)
        return False


def is_user_writable(path: Path) -> bool:
    """Whether this user could place what sits at `path`, asking the nearest existing ancestor so a
    file that has since been removed still answers about where it lived."""
    import os
    try:
        while not path.exists() and path != path.parent:
            path = path.parent
        return os.access(path, os.W_OK)
    except OSError:
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
    return any(norm == root or root in norm.parents for root in _SCRATCH_PATHS)


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
            m = _FORCED_COMMAND.search(line)
            if m is None:
                continue
            cmd = m.group(1)
            argv = cmd.split()
            # backdoor = a fetch/decode/scratch-EXEC shape (incl. via a wrapper or after a `;`/`&&`), or
            # the forced executable itself in a scratch dir. A scratch path used only as a data argument
            # (`rrsync … /var/tmp/repo`) is NOT — _FETCH_PIPE_EXEC and the argv[0] check distinguish them.
            if (_FETCH_PIPE_EXEC.search(cmd) or _SCRATCH_EXEC.search(cmd)
                    or (argv and _under_scratch(Path(argv[0])))):
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


_BASH_RC_FILES = (".bashrc", ".bash_profile", ".bash_login", ".profile")
_ZSH_RC_FILES = (".zshrc", ".zprofile", ".zshenv", ".zlogin")


def shell_rc_locations() -> list[Path]:
    """Where shell startup files actually live — RESOLVED, not assumed to sit in `$HOME`.

    ONE list: this module SCANS these for a planted line and the coverage probe CERTIFIES them, so
    the surface we read can never drift from the surface we certify. Hard-coding `$HOME`-relative
    names missed every layout that deliberately keeps `$HOME` clean — zsh under `$ZDOTDIR`, fish and
    nushell under XDG — where a fetch-to-shell line runs on every new terminal unseen. `conf.d` is
    returned as the DIRECTORY: it is sourced on every start and is the more attractive drop point."""
    home = Path.home()
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    zdotdir = Path(os.environ.get("ZDOTDIR") or home)
    locations = [home / name for name in _BASH_RC_FILES]
    locations += [zdotdir / name for name in _ZSH_RC_FILES]
    locations += [xdg / "fish" / "config.fish", xdg / "fish" / "conf.d",
                  xdg / "nushell" / "config.nu", xdg / "nushell" / "env.nu"]
    if sys.platform == "darwin":                    # nushell's macOS default, outside XDG
        support = home / "Library" / "Application Support" / "nushell"
        locations += [support / "config.nu", support / "env.nu"]
    return locations


def _iter_shell_rc() -> list[Path]:
    found: list[Path] = []
    for p in shell_rc_locations():
        try:
            if p.is_dir():                          # a conf.d drop-in dir — every file in it is sourced
                found += sorted(q for q in p.iterdir() if q.is_file())
            elif p.is_file():
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
            if _FETCH_PIPE_EXEC.search(line) or _SCRATCH_EXEC.search(line):
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


_GIT_EXEC_KEY = re.compile(
    r"^(?:core\.(?:editor|pager|sshcommand|askpass)"
    r"|sequence\.editor|alias\.[^=]+|filter\.[^=]+\.(?:clean|smudge|process)"
    # credential.(?:<url>.)?helper — a per-URL helper execs too, so the sub-key variant can't slip
    r"|diff\.(?:external|[^=]+\.command)|merge\.[^=]+\.driver|credential\.(?:[^=]+\.)?helper)$")

_GIT_BOOL = {"true", "false", "yes", "no", "on", "off", "1", "0"}

_GIT_BANG_KEY = re.compile(r"^(?:alias\.[^=]+|credential\.(?:[^=]+\.)?helper)$")


def _git_global_config() -> list[tuple[str, str]]:
    """(key, value) pairs from the GLOBAL git config only (never a scanned repo's local config).
    Git-absent / no config → []. Uses -z framing so a multi-line value can't desync the parse."""
    try:
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
        key, _, value = chunk.partition("\n")
        pairs.append((key.lower(), value))
    return pairs


def _global_git_config_paths() -> list[Path]:
    """Where git itself looks for a global config, in its own order of precedence."""
    override = os.environ.get("GIT_CONFIG_GLOBAL")
    if override:
        return [Path(override)]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return [base / "git" / "config", Path.home() / ".gitconfig"]


def _has_global_git_config() -> bool:
    """Whether git has a global configuration to read. `os.lstat`, not `Path.is_file()`, which
    answers False for a path it is not permitted to stat rather than raising."""
    for path in _global_git_config_paths():
        try:
            os.lstat(path)
            return True
        except FileNotFoundError:
            continue
        except NotADirectoryError:
            continue                      # a parent component is a file: nothing can live here
        except OSError:
            return True                   # it is there and unreadable, which is not "not there"
    return False


def git_config_predicate() -> str | None:
    """Separate "nothing is configured" from "the configuration was never read".

    The discriminator is the FILE, not the tool: a host with no global config has nothing to execute
    whether or not git is installed, while a config that exists and was not read is a surface this
    check did not cover."""
    if not _has_global_git_config():
        return None                       # nothing on disk to be configured to run
    try:
        listing = subprocess.run(["git", "config", "--global", "--list", "-z"],
                                 capture_output=True, text=True, errors="replace", timeout=10)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return ("A global git configuration exists but git could not be run to read it, so what it "
                "makes git execute was not examined.")
    if listing.returncode != 0:
        return ("A global git configuration exists but git would not list it, so what it makes git "
                "execute was not examined.")
    return None


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
            if (_FETCH_PIPE_EXEC.search(val) or _SCRATCH_EXEC.search(val)
                    or (argv and _under_scratch(Path(os.path.expanduser(argv[0]))))):
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
            probe = re.sub(r"^\s*!\s*", "", val) if _GIT_BANG_KEY.match(key) else val
            if _FETCH_PIPE_EXEC.search(probe) or _SCRATCH_EXEC.search(probe):
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
