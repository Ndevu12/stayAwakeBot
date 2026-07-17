#!/usr/bin/env python3
"""Symlink matcher — two escape-related anomalies, NEVER following the link (#1146, #1161).

The scanner walks with ``followlinks=False`` (a deliberate cycle/DoS guard), so a symlink is reported
but never descended into / opened. ``Path.resolve()`` only CANONICALIZES the path — it never reads the
target's contents, so a link to ``/`` or ``~/.ssh`` is free to resolve; symlink loops (ELOOP) raise and
are skipped (no infinite walk). Two findings:

  * ``symlink-write-redirect`` (CONFIRMED / critical, #1161) — a committed symlink (file OR directory)
    whose target escapes the repo into a $HOME/system WRITE-SINK: ``~/.ssh/authorized_keys``, a shell /
    editor / REPL startup file, git/cloud/service credentials, a GPG keyring, a PATH executable dir, or
    an OS-persistence directory (LaunchAgents, systemd, autostart, cron). A tool or agent told to WRITE
    the link's path writes THROUGH it into that sink — the GhostApproval / SymJacking attack. Such a
    link has no legitimate purpose, so it is decisive on its own (drives INFECTED). Sinks that ALSO
    exist as a shared PROJECT artifact (``.npmrc``, ``.vscode/``, ``.docker/config.json``) are
    deliberately excluded to stay false-positive-free — see ``_WRITE_SINKS``.

  * ``symlink-escapes-repo`` (HEURISTIC / high, #1146) — a DIRECTORY symlink escaping the repo root to
    a NON-sink target: it hides a whole code subtree from every content matcher (followlinks=False). An
    anomaly, not a payload — legitimate escaping dir links exist (dotfile repos, tooling fixtures) — so
    it is surfaced for review, never asserted as malware. Escaping FILE symlinks to non-sink targets are
    overwhelmingly benign dev-env links (a venv ``bin/python -> /usr/.../python3``) and remain a
    documented residual.

The *contents* behind any symlink stay unscanned by design; only the link's own metadata is inspected.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher


# Sensitive WRITE-SINKS — $HOME/system locations a victim's tools write to, where a planted symlink
# redirects the write into persistence or RCE (GhostApproval / SymJacking, #1161). Matched against the
# raw link text AND the canonical resolved path, by PATH COMPONENT (bounded by `/` or end), NOT a bare
# substring — so a benign path that merely contains one of these words as a longer segment does not hit.
# Matched CASE-INSENSITIVELY: on a case-insensitive FS (macOS/Windows) `~/.SSH/authorized_keys` is the
# SAME file as `~/.ssh/...`, so a case-flip must not evade.
#
# Scope discipline (why some obvious-looking targets are NOT here): only a location a repo would NEVER
# legitimately symlink to stays CONFIRMED. Files that ALSO exist as a PROJECT artifact — `.npmrc`,
# `.docker/config.json`, `.vscode/`, `.claude/`, `.cursor/` — are routinely SHARED across a workspace by
# a sibling/superproject symlink (a real, benign pattern), so flagging them as confirmed-malware is a
# false positive; they are deliberately excluded (an escaping DIRECTORY link to one is still surfaced as
# the `symlink-escapes-repo` HEURISTIC). The label goes into the evidence.
def _sink(pattern: str, label: str) -> tuple[re.Pattern[str], str]:
    return re.compile(pattern, re.IGNORECASE), label


_WRITE_SINKS: list[tuple[re.Pattern[str], str]] = [
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


def _sink_label(raw_target: str, resolved: Path) -> str | None:
    """The sink label if the (escaping) symlink target names a sensitive write-sink, else None. Matches
    the raw link text AND the canonical path, so both a relative ``../../.ssh/authorized_keys`` and an
    absolute ``/home/u/.ssh/id_ed25519`` hit."""
    hay = raw_target + "\n" + str(resolved)
    for rx, label in _WRITE_SINKS:
        if rx.search(hay):
            return label
    return None


def _finding(sig: dict, rel: str, evidence: str) -> Finding:
    return Finding(
        signature_id=sig["id"], category=sig["category"], severity=Severity.parse(sig["severity"]),
        path=rel, description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=evidence, vector=sig["category"])


def _classify(p: Path, repo_root: Path, resolved_root: Path,
              redirect_sig: dict | None, escape_sig: dict | None, is_dir: bool) -> Finding | None:
    """The finding this symlink warrants, or None. Only ESCAPING links matter: a write-redirect sink is
    outside the repo, and a scan-evasion escape is by definition outside. An intra-repo link (a monorepo
    alias, a link to the repo's OWN dotfile) is neither. resolve() canonicalizes without reading the
    target; ELOOP/unresolvable/unreadable → skipped (no DoS, no crash)."""
    try:
        if not p.is_symlink():
            return None
    except OSError:
        return None
    try:
        resolved = p.resolve()              # canonicalize only — never reads target; loop-safe
    except (OSError, RuntimeError):
        return None                           # ELOOP / unresolvable → skip
    if resolved == resolved_root or resolved_root in resolved.parents:
        return None                           # stays inside the repo → normal
    try:
        raw = os.readlink(p)
    except OSError:
        raw = "?"
    try:
        rel = str(p.relative_to(repo_root))
    except ValueError:
        rel = str(p)
    if redirect_sig is not None:
        label = _sink_label(raw, resolved)
        if label is not None:                 # escaping → a sensitive write-sink → CONFIRMED critical
            return _finding(redirect_sig, rel, f"symlink → {raw} redirects a write into {label}")
    if escape_sig is not None and is_dir:      # escaping directory → non-sink → scan-evasion HEURISTIC
        return _finding(escape_sig, rel, f"symlink → {raw} resolves outside the repo root (contents unscanned)")
    return None


class SymlinkMatcher(Matcher):
    handles = "symlink"

    def scan(self, target, signatures):
        by_id = {s["id"]: s for s in signatures}
        redirect_sig = by_id.get("symlink-write-redirect")
        escape_sig = by_id.get("symlink-escapes-repo")
        if redirect_sig is None and escape_sig is None:
            return []
        try:
            root = target.root.resolve()
        except (OSError, RuntimeError):
            return []
        exclude = getattr(target.opts, "exclude_dirs", set())
        findings: list[Finding] = []
        for dirpath, dirnames, filenames in os.walk(target.root):   # followlinks=False (default)
            # Classify DIRECTORY entries BEFORE pruning for descent, so a write-redirect symlink whose
            # NAME is an excluded dir (`dist -> ~/.ssh`, `node_modules -> ~/.ssh`) is still caught —
            # `dist`/`build` are exactly where build tools write. Pruning only stops DESCENT, and
            # os.walk(followlinks=False) never descends a symlink anyway. For an excluded name we run the
            # write-redirect check ONLY (escape_sig=None): a benign build-output dir link escaping to a
            # non-sink stays silent as it did before, rather than becoming a new scan-evasion heuristic.
            for name in dirnames:
                esc = None if name in exclude else escape_sig
                f = _classify(Path(dirpath) / name, target.root, root, redirect_sig, esc, True)
                if f is not None:
                    findings.append(f)
            dirnames[:] = [d for d in dirnames if d not in exclude]  # THEN prune descent
            # FILE symlinks: a write-redirect can be a file link (the canonical GhostApproval shape); a
            # scan-evasion escape is only meaningful for a directory, so `is_dir=False` drops the escape.
            for name in filenames:
                f = _classify(Path(dirpath) / name, target.root, root, redirect_sig, escape_sig, False)
                if f is not None:
                    findings.append(f)
        return findings
