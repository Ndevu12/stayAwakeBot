#!/usr/bin/env python3
"""Autorun SURFACE enumeration (#1333) — the finite set of places malware arranges to be re-executed.

Payloads are unbounded; the LOCATIONS that re-run a payload are finite and enumerable. This module
turns each location into a structured `AutorunEntry` — what it runs (the referenced executable + argv),
its persistence shape (run-at-load / keep-alive / poll interval), and a content digest — so the
attribution layers (provenance, content-shape, novelty, correlation) can grade it *without* needing a
signature for the payload. Read-only, stdlib-only; a non-regular file is never opened (the #1226 FIFO
hazard). Locations are sourced from the detection probes' own definitions (single source of truth).

v1 covers the catastrophic persistence surface — macOS LaunchAgents + Linux systemd user units (where
the rotation wiper lives). The surface is a registry: shell rc, git hooks, agent (`~/.claude`) hooks,
VS Code tasks, and npm lifecycle extend it without touching the grading layers.
"""
from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from stayawake.utils import pathsafe
from .. import os_service


@dataclass
class AutorunEntry:
    """One re-execution point. `argv` is what it runs (argv[0] = the referenced executable); `body`
    is the raw config text (for the digest + content-shape); `persistence` names the re-run triggers."""
    location: str                       # "launch-agent" | "systemd-user"
    path: Path                          # the .plist / .service / .timer file
    argv: list[str] = field(default_factory=list)
    body: str = ""
    # Every command line this entry executes — argv is only the first. The parser owns the config
    # grammar, so it publishes these rather than each consumer re-deriving them.
    shell_lines: list[str] = field(default_factory=list)
    # Whether `argv` came from a structured source (a plist array) or a naive `.split()` that loses
    # quoting. Only the parser knows, and a consumer that guessed got it wrong both ways.
    argv_is_exact: bool = True
    persistence: list[str] = field(default_factory=list)

    @property
    def exec_path(self) -> str | None:
        return self.argv[0] if self.argv else None

    def key(self) -> str:
        """Stable identity for the baseline (the location on disk)."""
        return str(self.path)

    def digest(self) -> str:
        """Content fingerprint — a changed body re-surfaces the entry even if its path is 'known'."""
        return sha256(self.body.encode("utf-8", "replace")).hexdigest()

    def shape_text(self) -> str:
        """The text the content-shape detectors run over: the referenced command line joined with the
        raw body, so a fetch-exec in either the argv or the surrounding config is seen."""
        return " ".join(self.argv) + "\n" + self.body


def _iter_files(dirs, suffixes) -> list[Path]:
    """Regular files under `dirs` whose name ends with one of `suffixes`. A missing/unreadable dir is
    skipped; a non-regular entry is skipped (never opened) via the shared `pathsafe` guard."""
    out: list[Path] = []
    for d in dirs:
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        out += [p for p in entries
                if p.name.lower().endswith(suffixes) and pathsafe.is_regular_file(p)]
    return out


# ── macOS LaunchAgents (plist) ──────────────────────────────────────────────────────────

def _parse_launch_agent(path: Path) -> AutorunEntry | None:
    raw = pathsafe.read_regular_bytes(path)
    if raw is None:
        return None
    try:
        data = plistlib.loads(raw)                 # handles XML and binary plists
    except Exception:                              # noqa: BLE001 — a malformed plist → no argv, still surfaced
        data = None
    argv: list[str] = []
    persistence: list[str] = []
    if isinstance(data, dict):
        prog = data.get("ProgramArguments")
        if isinstance(prog, list) and prog:
            argv = [str(x) for x in prog]
        elif isinstance(data.get("Program"), str):
            argv = [data["Program"]]
        if data.get("RunAtLoad"):
            persistence.append("run-at-load")
        if data.get("KeepAlive"):
            persistence.append("keep-alive")
        iv = data.get("StartInterval")
        if isinstance(iv, int):
            persistence.append(f"poll-interval={iv}s")
        if data.get("StartCalendarInterval"):
            persistence.append("scheduled")
        if data.get("WatchPaths") or data.get("QueueDirectories"):
            persistence.append("watch-triggered")
    body = raw.decode("utf-8", "replace")
    # A plist plistlib cannot parse yields no argv (the entry is still surfaced), so the body is the
    # only place its command survives — keep it in shell context rather than losing it silently.
    return AutorunEntry(location="launch-agent", path=path, argv=argv, body=body,
                        shell_lines=[" ".join(argv)] if argv else [body],
                        persistence=persistence)


# ── Linux systemd user units (ini-ish) ──────────────────────────────────────────────────

_EXECSTART = re.compile(r"^\s*ExecStart\s*=\s*(.*)$", re.MULTILINE)
# EVERY executed directive: a oneshot unit may carry several ExecStart=, and ExecStartPre/Post,
# ExecReload, ExecCondition and ExecStopPost each run a command line argv never sees.
_EXEC_DIRECTIVE = re.compile(r"^\s*Exec[A-Za-z]*\s*=\s*(.*)$", re.MULTILINE)
_CONTINUATION = re.compile(r"\\\s*\n\s*")
_TIMER_KEY = re.compile(r"^\s*(OnUnitActiveSec|OnCalendar|OnBootSec|OnUnitInactiveSec)\s*=\s*(.*)$",
                        re.MULTILINE)


def _strip_modifiers(line: str) -> str:
    """systemd allows leading modifier chars (`-@!+:`) before the binary — strip them so what
    remains is the real command line."""
    line = line.strip()
    while line[:1] in ("-", "@", "!", "+", ":"):
        line = line[1:].lstrip()
    return line


def _systemd_shell_lines(text: str) -> list[str]:
    """Every command line the unit executes, with backslash continuations joined first so a
    directive split across lines is not truncated at the first one."""
    joined = _CONTINUATION.sub(" ", text)
    return [ln for ln in (_strip_modifiers(m.group(1)) for m in _EXEC_DIRECTIVE.finditer(joined)) if ln]


def _systemd_argv(execstart: str) -> list[str]:
    """The argv of an ExecStart line. systemd allows leading modifier chars (`-@!+:`) before the
    binary — strip them so argv[0] is the real executable. A naive split is fine for provenance
    (we only need argv[0]'s path + a shape scan of the whole line)."""
    return _strip_modifiers(execstart).split()


def _parse_systemd_unit(path: Path) -> AutorunEntry | None:
    text = pathsafe.read_regular_text(path)
    if text is None:
        return None
    argv: list[str] = []
    m = _EXECSTART.search(text)
    if m:
        argv = _systemd_argv(m.group(1))
    persistence: list[str] = []
    if path.name.endswith(".timer") or _TIMER_KEY.search(text):
        for km in _TIMER_KEY.finditer(text):
            persistence.append(f"timer:{km.group(1)}={km.group(2).strip()[:32]}")
    if re.search(r"^\s*WantedBy\s*=", text, re.MULTILINE):
        persistence.append("enabled")
    return AutorunEntry(location="systemd-user", path=path, argv=argv, body=text,
                        shell_lines=_systemd_shell_lines(text), persistence=persistence,
                        argv_is_exact=False)


def enumerate_entries() -> list[AutorunEntry]:
    """Every autorun entry on the catastrophic persistence surface (launch agents + systemd user
    units/timers), parsed. Dispatch is by FILE EXTENSION across the user-owned persistence dirs
    (`.plist` → launch agent, `.service`/`.timer` → systemd) — not by directory name — so it is
    robust and testable. Order is deterministic (sorted by path within each type)."""
    dirs = os_service.user_persistence_dirs()
    entries: list[AutorunEntry] = []
    for p in _iter_files(dirs, (".plist",)):
        e = _parse_launch_agent(p)
        if e is not None:
            entries.append(e)
    for p in _iter_files(dirs, (".service", ".timer")):
        e = _parse_systemd_unit(p)
        if e is not None:
            entries.append(e)
    return entries
