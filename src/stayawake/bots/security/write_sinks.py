#!/usr/bin/env python3
"""Where a planted symlink redirects a write — the one table three callers ask.

Used by the symlink matcher (to grade a link), by target resolution (to decide whether to read
through one) and by the reader itself (to refuse to open one).
"""
from __future__ import annotations

import re
from pathlib import Path


# Sensitive WRITE-SINKS — $HOME/system locations a victim's tools write to, where a planted symlink
# raw link text AND the canonical resolved path, by PATH COMPONENT (bounded by `/` or end), NOT a bare
# substring — so a benign path that merely contains one of these words as a longer segment does not hit.
# Matched CASE-INSENSITIVELY: on a case-insensitive FS (macOS/Windows) `~/.SSH/authorized_keys` is the
# SAME file as `~/.ssh/...`, so a case-flip must not evade.
#
# Scope discipline (why some obvious-looking targets are NOT here): only a location a repo would NEVER
# legitimately symlink to stays CONFIRMED. Files that ALSO exist as a PROJECT artifact — `.npmrc`,
# `.docker/config.json`, `.vscode/`, `.claude/`, `.cursor/` — are routinely SHARED across a workspace by
# a sibling/superproject symlink (a real, benign pattern), so flagging them as confirmed-malware is a
# the `symlink-escapes-repo` HEURISTIC). The label goes into the evidence.
def _sink(pattern: str, label: str) -> tuple[re.Pattern[str], str]:
    return re.compile(pattern, re.IGNORECASE), label


WRITE_SINKS: list[tuple[re.Pattern[str], str]] = [
    _sink(r"(?:^|/)\.ssh(?:/|$)", "SSH keys/config (~/.ssh)"),
    _sink(r"(?:^|/)\.(?:bashrc|bash_profile|bash_login|bash_aliases|zshrc|zprofile|zshenv|zlogin"
          r"|profile|kshrc|cshrc|tcshrc)$", "shell startup file"),
    _sink(r"(?:^|/)\.config/fish/config\.fish$", "fish startup file"),
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
    _sink(r"(?:^|/)\.local/bin(?:/|$)|(?:^|/)\.cargo/bin(?:/|$)|(?:^|/)\.deno/bin(?:/|$)",
          "PATH executable dir"),
    # Editor startup that runs code on launch ($HOME-only; the project `.vscode/` is excluded above,
    # but the user-global VS Code settings dir is not a project artifact).
    _sink(r"(?:^|/)\.(?:vimrc|gvimrc|ideavimrc)$|(?:^|/)\.vim(?:/|$)|(?:^|/)\.config/nvim(?:/|$)"
          r"|(?:^|/)\.emacs$|(?:^|/)\.emacs\.d(?:/|$)|(?:^|/)\.config/emacs(?:/|$)"
          r"|(?:^|/)\.config/Code/User(?:/|$)", "editor startup (exec-on-launch)"),
    _sink(r"(?:^|/)\.ipython(?:/|$)|(?:^|/)\.jupyter(?:/|$)", "REPL/notebook startup"),
    _sink(r"(?:^|/)\.(?:gdbinit|lldbinit)$|(?:^|/)\.tmux\.conf$|(?:^|/)\.Rprofile$",
          "tool startup (exec-on-launch)"),
]


def sink_label(raw_target: str, resolved: Path) -> str | None:
    """The sink label if the (escaping) symlink target names a sensitive write-sink, else None. Matches
    the raw link text AND the canonical path, so both a relative ``../../.ssh/authorized_keys`` and an
    absolute ``/home/u/.ssh/id_ed25519`` hit."""
    hay = raw_target + "\n" + str(resolved)
    for rx, label in WRITE_SINKS:
        if rx.search(hay):
            return label
    return None


