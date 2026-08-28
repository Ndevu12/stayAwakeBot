#!/usr/bin/env python3
"""Autorun SURFACE enumeration — the finite set of places malware arranges to be re-executed."""
from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from stayawake.utils import pathsafe
from stayawake.utils.pathsafe import grade
from .. import os_service


@dataclass
class AutorunEntry:
    """One re-execution point. `argv` is what it runs (argv[0] = the referenced executable); `body`
    is the raw config text (for the digest + content-shape); `persistence` names the re-run triggers."""
    location: str
    path: Path
    argv: list[str] = field(default_factory=list)
    body: str = ""
    shell_lines: list[str] = field(default_factory=list)
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


def _iter_files(dirs, suffixes, unread: list) -> list[Path]:
    out: list[Path] = []
    for d in dirs:
        state = grade(d)
        if state == "absent":
            continue
        if state == "unverified":
            unread.append(d)
            continue
        try:
            entries = sorted(d.iterdir())
        except OSError:
            unread.append(d)
            continue
        for p in entries:
            if not p.name.lower().endswith(suffixes):
                continue
            state = grade(p)
            if state == "unverified":
                unread.append(p)
            elif state == "ok" and pathsafe.is_regular_file(p):
                out.append(p)
    return out


# ── macOS LaunchAgents (plist) ──────────────────────────────────────────────────────────

def _parse_launch_agent(path: Path) -> AutorunEntry | None:
    raw = pathsafe.read_regular_bytes(path)
    if raw is None:
        return None
    try:
        data = plistlib.loads(raw)
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


def enumerate_entries() -> tuple[list[AutorunEntry], list[Path]]:
    """Every autorun entry on the catastrophic persistence surface (launch agents + systemd user
    units/timers), parsed. Dispatch is by FILE EXTENSION across the user-owned persistence dirs
    (`.plist` → launch agent, `.service`/`.timer` → systemd) — not by directory name — so it is
    robust and testable. Order is deterministic (sorted by path within each type)."""
    dirs = os_service.user_persistence_dirs()
    unread: list[Path] = []
    entries: list[AutorunEntry] = []
    for p in _iter_files(dirs, (".plist",), unread):
        e = _parse_launch_agent(p)
        if e is not None:
            entries.append(e)
    for p in _iter_files(dirs, (".service", ".timer"), unread):
        e = _parse_systemd_unit(p)
        if e is not None:
            entries.append(e)
    return entries, unread
