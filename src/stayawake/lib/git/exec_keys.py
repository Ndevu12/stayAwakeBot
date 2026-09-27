#!/usr/bin/env python3
"""The configuration keys whose value git executes, read from `lib/data/git_exec_keys.yml`."""
from __future__ import annotations

import functools
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

KEYS_FILE = Path(__file__).resolve().parent.parent / "data" / "git_exec_keys.yml"

COMMAND = "command"
AFTER_BANG = "after-bang"
UNLESS_BOOLEAN = "unless-boolean"
HOOKS_DIRECTORY = "hooks-directory"
EXT_TRANSPORT = "ext-transport"
EXT_ADDRESS = "ext-address"
ENABLES_TRANSPORT = "enables-transport"
_RUNS = frozenset({COMMAND, AFTER_BANG, UNLESS_BOOLEAN, HOOKS_DIRECTORY, EXT_TRANSPORT,
                   EXT_ADDRESS, ENABLES_TRANSPORT})
_DRIVERS = frozenset({"filter", "diff", "merge"})
_BOOLEAN_WORDS = frozenset({"true", "false", "yes", "no", "on", "off", "1", "0", ""})
_EXT_PREFIX = "ext::"


@dataclass(frozen=True)
class ExecKey:
    """One entry of the key list."""

    key: str
    runs: str = COMMAND
    bang: bool = False
    driver: str | None = None
    fires_on_its_own: bool = False

    def matches(self, key: str) -> bool:
        """Say whether a listed key is this entry. Takes the key as git lists it. Returns True
        when it is."""
        return fnmatchcase(key.lower(), self.key)

    def command(self, key: str, value: str | None) -> str | None:
        """Read the command line git runs for `key` set to `value`. Takes the key as git lists it
        and its value (None for a bare key). Returns the command, or None when this value runs
        nothing."""
        if self.runs == EXT_TRANSPORT:
            sub = subsection(key) or ""
            return sub[len(_EXT_PREFIX):] if sub.lower().startswith(_EXT_PREFIX) else None
        if self.runs in (HOOKS_DIRECTORY, ENABLES_TRANSPORT):
            return None
        text = (value or "").strip()
        if not text:
            return None
        if self.runs == UNLESS_BOOLEAN and text.lower() in _BOOLEAN_WORDS:
            return None
        if self.runs == AFTER_BANG and not text.startswith("!"):
            return None
        if self.runs == EXT_ADDRESS:
            return text[len(_EXT_PREFIX):] if text.lower().startswith(_EXT_PREFIX) else None
        return text[1:].lstrip() if self.bang and text.startswith("!") else text


def subsection(key: str) -> str | None:
    """Take a key as git lists it. Returns its subsection, case kept, or None when it has none."""
    first, last = key.find("."), key.rfind(".")
    return key[first + 1:last] if 0 <= first < last else None


def _entry(raw: dict) -> ExecKey:
    key = raw.get("key")
    runs = raw.get("runs", COMMAND)
    driver = raw.get("driver")
    if not isinstance(key, str) or not key or key != key.lower():
        raise ValueError(f"git exec key entry needs a lowercase `key`: {raw!r}")
    if runs not in _RUNS:
        raise ValueError(f"git exec key {key}: unknown `runs` {runs!r}")
    if driver is not None and driver not in _DRIVERS:
        raise ValueError(f"git exec key {key}: unknown `driver` {driver!r}")
    return ExecKey(key=key, runs=runs, bang=bool(raw.get("bang", False)), driver=driver,
                   fires_on_its_own=bool(raw.get("fires_on_its_own", False)))


@functools.lru_cache(maxsize=None)
def exec_keys(path: Path = KEYS_FILE) -> tuple[ExecKey, ...]:
    """Load the key list. Takes the file (default: the shipped list). Returns its entries in file
    order; raises ValueError on a malformed file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return tuple(_entry(raw) for raw in data.get("keys") or ())


@functools.lru_cache(maxsize=None)
def plain_programs(path: Path = KEYS_FILE) -> tuple[frozenset[str], frozenset[str]]:
    """Load the programs and interpreter modules a self-firing key may name and still be an
    ordinary tool. Takes the file (default: the shipped list). Returns both sets, lowercased."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return (frozenset(str(p).lower() for p in data.get("plain_programs") or ()),
            frozenset(str(m).lower() for m in data.get("plain_modules") or ()))


def rule_for(key: str) -> ExecKey | None:
    """Look up a key as git lists it. Returns its entry, or None when git does not execute it."""
    return next((rule for rule in exec_keys() if rule.matches(key)), None)
