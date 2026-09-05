#!/usr/bin/env python3
"""Autorun SURFACE enumeration — the finite set of places malware arranges to be re-executed."""
from __future__ import annotations

import codecs
import os
import plistlib
import re
from dataclasses import dataclass, field
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path

from stayawake.utils import pathsafe
from stayawake.utils.pathsafe import grade
from stayawake.bots.security import hookscript
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

_LAUNCH_KEYS = frozenset({"ProgramArguments", "Program", "RunAtLoad", "KeepAlive", "StartInterval",
                          "StartCalendarInterval", "WatchPaths", "QueueDirectories"})
_LEAF_TAGS = frozenset({"key", "string", "integer", "real", "true", "false", "date", "data"})


class _LaunchKeyReader(HTMLParser):
    """Read the top-level launch keys out of plist text the strict parser rejected."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found: dict = {}
        self.complete = True
        self._depth = 0
        self._done = False
        self._key: str | None = None
        self._open: str | None = None
        self._text: list[str] = []
        self._items: list[str] | None = None
        self._container: str | None = None

    def handle_starttag(self, tag, attrs):
        if self._done:
            return
        if self._container is not None:
            self.found[self._container] = True
        if self._open is not None:
            self.complete = False
        elif tag in ("dict", "array"):
            if self._items is not None:
                self.complete = False
            elif self._depth == 1 and self._key == "ProgramArguments" and tag == "array":
                self._items = []
            elif self._depth == 1 and self._key in _LAUNCH_KEYS:
                self.found[self._key] = False
                self._container, self._key = self._key, None
            self._depth += 1
        elif tag in _LEAF_TAGS:
            self._open, self._text = tag, []
        elif self._items is not None:
            self.complete = False

    def handle_endtag(self, tag):
        if self._done:
            return
        if self._open is not None and tag != self._open:
            self.complete = False
        elif tag in ("dict", "array"):
            self._depth -= 1
            if self._depth == 1:
                self._container = None
            if tag == "dict" and self._depth == 0:
                self._done = True
            if tag == "array" and self._items is not None and self._depth == 1:
                self.found["ProgramArguments"] = self._items
                self._items, self._key = None, None
        elif tag == self._open:
            self._close_leaf(tag, "".join(self._text))

    def _close_leaf(self, tag: str, value: str):
        self._open = None
        if self._items is not None:
            if tag == "string" and self._depth == 2:
                self._items.append(value)
            else:
                self.complete = False
        elif tag == "key":
            if self._depth == 1:
                self._key = value
        elif self._depth == 1 and self._key in _LAUNCH_KEYS:
            self.found[self._key] = _leaf_value(tag, value)
            self._key = None

    def handle_data(self, data):
        if self._open is not None and not self._done:
            self._text.append(data)

    def unknown_decl(self, data):
        if self._done:
            return
        if self._open is not None and data.startswith("CDATA["):
            self._text.append(data[len("CDATA["):])
        elif self._open is not None:
            self.complete = False

    def handle_comment(self, data):
        if self._open is None or self._done:
            return
        if data.startswith("[CDATA[") and data.endswith("]]"):
            self._text.append(data[len("[CDATA["):-2])
        else:
            self.complete = False

    def handle_decl(self, data):
        if self._open is not None and not self._done:
            self.complete = False

    handle_pi = handle_decl

    def readable(self) -> bool:
        """Return True if the command keys were read without loss."""
        return (self.complete and self._open is None and self._items is None
                and (isinstance(self.found.get("ProgramArguments"), list)
                     or isinstance(self.found.get("Program"), str)))


def _leaf_value(tag: str, value: str):
    if tag == "true":
        return True
    if tag == "false":
        return False
    if tag == "integer":
        return int(value) if value.strip().lstrip("-").isdigit() else None
    if tag == "real":
        try:
            return float(value)
        except ValueError:
            return None
    if tag == "data":
        return bool(value.strip())
    return value if tag == "string" else True


_MAX_READ = 1 << 20


_MARKED_ENCODINGS = ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
                     (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"))


def _plist_text(raw: bytes) -> str:
    """Return plist bytes as text, honouring a byte-order mark that yields plist text."""
    for mark, encoding in _MARKED_ENCODINGS:
        if raw.startswith(mark):
            text = raw.decode(encoding, "replace")
            if "<plist" in text or "<dict" in text:
                return text
            break
    return raw.decode("utf-8", "replace")


def _launch_keys(raw: bytes) -> tuple[dict, bool]:
    """Return the launch keys of a plist and whether they were read without loss."""
    try:
        data = plistlib.loads(raw)
    except Exception:                              # noqa: BLE001
        if len(raw) > _MAX_READ:
            return {}, False
        text = _plist_text(raw)
        if "<!ENTITY" in text:
            return {}, False
        reader = _LaunchKeyReader()
        try:
            reader.feed(text)
            reader.close()
        except Exception:                          # noqa: BLE001
            return {}, False
        return (reader.found, True) if reader.readable() else ({}, False)
    return (data if isinstance(data, dict) else {}), True


def _parse_launch_agent(path: Path) -> AutorunEntry | None:
    raw = pathsafe.read_regular_bytes(path)
    if raw is None:
        return None
    data, readable = _launch_keys(raw)
    argv: list[str] = []
    persistence: list[str] = []
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
    body = _plist_text(raw)
    return AutorunEntry(location="launch-agent", path=path, argv=argv, body=body,
                        shell_lines=[" ".join(argv)] if argv else ([] if readable else [body]),
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


# ── git hooks run from a template or a seeded repository ────────────────────────────────

def git_hook_dirs() -> list[Path]:
    """Return every hooks directory git runs on this account through saw's template mechanism."""
    return hookscript.hook_dirs()


def _executable_files(d: Path, unread: list) -> list[Path]:
    out: list[Path] = []
    state = grade(d)
    if state == "absent":
        return out
    if state == "unverified":
        unread.append(d)
        return out
    try:
        entries = sorted(d.iterdir())
    except OSError:
        unread.append(d)
        return out
    for p in entries:
        state = grade(p)
        if state == "unverified":
            unread.append(p)
        elif state == "ok" and pathsafe.is_regular_file(p) and os.access(p, os.X_OK):
            out.append(p)
    return out


def _parse_git_hook(path: Path) -> AutorunEntry | None:
    text = pathsafe.read_regular_text(path)
    if text is None:
        return None
    argv = hookscript.saw_command(text) or [str(path)]
    body = text
    for sibling in hookscript.sourced_siblings(text, path):
        sourced = pathsafe.read_regular_text(sibling)
        if sourced is not None:
            body += "\n" + sourced[:hookscript._MAX_SIBLING]
    return AutorunEntry(location=hookscript.LOCATION, path=path, argv=argv, body=body,
                        shell_lines=[ln for ln in body.splitlines() if ln.strip()],
                        persistence=[f"git-event:{path.name}"])


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
    for d in git_hook_dirs():
        for p in _executable_files(d, unread):
            e = _parse_git_hook(p)
            if e is not None:
                entries.append(e)
    return entries, unread
