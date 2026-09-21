#!/usr/bin/env python3
"""Where a planted symlink redirects a write."""
from __future__ import annotations

import os
import re
from pathlib import Path


def _sink(pattern: str, label: str) -> tuple[re.Pattern[str], str]:
    return re.compile(pattern, re.IGNORECASE), label


_HOME_ROOT = r"(?:/Users|/home)/[^/]{1,64}|/root"


WRITE_SINKS: list[tuple[re.Pattern[str], str]] = [
    _sink(r"(?:^|/)\.ssh(?:/|$)", "SSH keys/config (~/.ssh)"),
    _sink(r"(?:^|/)\.(?:bashrc|bash_profile|bash_login|bash_aliases|zshrc|zprofile|zshenv|zlogin"
          r"|profile|kshrc|cshrc|tcshrc)$", "shell startup file"),
    _sink(r"(?:^|/)\.config/fish/(?:config\.fish$|conf\.d(?:/|$))", "fish startup file"),
    _sink(r"(?:^|/)\.gitconfig$|(?:^|/)\.config/git/config$", "git config (exec-on-git-op)"),
    _sink(r"(?:^|/)\.aws(?:/|$)|(?:^|/)\.config/gcloud(?:/|$)|(?:^|/)\.kube/config$"
          r"|(?:^|/)\.azure(?:/|$)", "cloud credential"),
    _sink(r"(?:^|/)\.(?:netrc|pypirc|terraformrc)$|(?:^|/)\.gem/credentials$", "service credential"),
    _sink(r"(?:^|/)\.gnupg(?:/|$)", "GPG keyring"),
    # OS / user persistence — launch agents, systemd units, autostart, cron (user AND system paths).
    _sink(r"(?:^|/)Library/Launch(?:Agents|Daemons)(?:/|$)|(?:^|/)\.config/(?:systemd|autostart)(?:/|$)"
          r"|(?:^|/)\.local/share/systemd/user(?:/|$)|/etc/systemd/system(?:/|$)|/etc/profile\.d(?:/|$)"
          r"|/etc/cron\.(?:d|daily|hourly|weekly|monthly)(?:/|$)|/var/spool/cron(?:/|$)"
          r"|(?:^|/)\.crontab$", "startup/persistence"),
    # $HOME executable-search dirs — a planted/overwritten binary here shadows a command on PATH (RCE).
    _sink(r"(?:^|/)\.local/bin(?:/|$)|(?:^|/)\.cargo/bin(?:/|$)|(?:^|/)\.deno/bin(?:/|$)"
          r"|(?:^|/)\.bun/bin(?:/|$)", "PATH executable dir"),
    _sink(rf"^(?:{_HOME_ROOT})/\.[^/]{{1,64}}/(?:bin|sbin|shims)(?:/|$)", "PATH executable dir"),
    _sink(rf"^(?:{_HOME_ROOT})/\.[^/]{{1,64}}/(?:versions|installs|candidates)"
          rf"/(?:[^/]{{1,64}}/){{1,3}}(?:bin|shims)(?:/|$)", "PATH executable dir"),
    _sink(r"(?:^|/)(?:site|dist)-packages/[^/]{1,255}\.pth$"
          r"|(?:^|/)(?:site|user)customize\.py$", "Python startup hook (exec-on-start)"),
    # Editor startup that runs code on launch ($HOME-only; the project `.vscode/` is excluded above,
    # but the user-global VS Code settings dir is not a project artifact).
    _sink(r"(?:^|/)\.(?:vimrc|gvimrc|ideavimrc)$|(?:^|/)\.vim(?:/|$)|(?:^|/)\.config/nvim(?:/|$)"
          r"|(?:^|/)\.emacs$|(?:^|/)\.emacs\.d(?:/|$)|(?:^|/)\.config/emacs(?:/|$)"
          r"|(?:^|/)\.config/Code/User(?:/|$)", "editor startup (exec-on-launch)"),
    _sink(r"(?:^|/)\.ipython(?:/|$)|(?:^|/)\.jupyter(?:/|$)", "REPL/notebook startup"),
    _sink(r"(?:^|/)\.(?:gdbinit|lldbinit)$|(?:^|/)\.tmux\.conf$|(?:^|/)\.Rprofile$",
          "tool startup (exec-on-launch)"),
]


CONTROL_EXEC_LABEL = "git's own exec surface (hooks/config)"

_CONTROL_SUFFIX = ".git"
_NESTED_CONTROL = ("modules", "worktrees")
_EXEC_TREE = "hooks"
_EXEC_FILES = ("config", "config.worktree")


def _reaches_exec(rest: list[str]) -> bool:
    """Walk what follows a control directory. Takes the remaining path components. Returns True when
    they name the directory itself, its hooks, its config, or the same inside a nested one."""
    if not rest:
        return True
    head = rest[0].lower()
    if head == _EXEC_TREE:
        return True
    if len(rest) == 1 and head in _EXEC_FILES:
        return True
    if head in _NESTED_CONTROL:
        return any(_reaches_exec(rest[i:]) for i in range(1, len(rest) + 1))
    return False


def control_exec_sink(landing: Path, known: set[str] | None = None) -> bool:
    """Ask whether a link reaches what git executes from. Takes where it lands and the paths the
    repository itself named, when they could be asked for. Returns True when it does."""
    here = str(landing)
    folded = here.lower()
    for named in (known or ()):
        lowered = named.lower()
        if folded == lowered or folded.startswith(lowered + os.sep):
            return True
    parts = here.replace(os.sep, "/").split("/")
    return any(part.lower().endswith(_CONTROL_SUFFIX) and _reaches_exec(parts[i + 1:])
               for i, part in enumerate(parts))


def sink_label(raw_target: str, resolved: Path) -> str | None:
    """The sink label if the (escaping) symlink target names a sensitive write-sink, else None. Matches
    the raw link text AND the canonical path, so both a relative ``../../.ssh/authorized_keys`` and an
    absolute ``/home/u/.ssh/id_ed25519`` hit."""
    for rx, label in WRITE_SINKS:
        if rx.search(raw_target) or rx.search(str(resolved)):
            return label
    return None


