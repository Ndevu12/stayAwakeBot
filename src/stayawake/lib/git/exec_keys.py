#!/usr/bin/env python3
"""The configuration keys whose value git executes, read from `lib/data/git_exec_keys.yml`."""
from __future__ import annotations

import functools
import os
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
ABSOLUTE_PATH = "absolute-path"
_RUNS = frozenset({COMMAND, AFTER_BANG, UNLESS_BOOLEAN, HOOKS_DIRECTORY, EXT_TRANSPORT,
                   EXT_ADDRESS, ENABLES_TRANSPORT, ABSOLUTE_PATH})
_DRIVERS = frozenset({"filter", "diff", "merge"})
_BOOLEAN_WORDS = frozenset({"true", "false", "yes", "no", "on", "off", "1", "0", ""})
_EXT_PREFIX = "ext::"
_OVERRIDE_FIELDS = frozenset({"setting", "environment", "value", "reset", "refuse"})


@dataclass(frozen=True)
class Override:
    """How a folder's own value of a key is kept from running. `setting` or `environment` names
    what is set to `value` instead of the key, `reset` names the key whose empty value clears the
    list this key adds to, and `refuse` says nothing keeps it from running. With none of these, the
    key itself is set again."""

    setting: str | None = None
    environment: str | None = None
    value: str = ""
    reset: str | None = None
    refuse: bool = False


@dataclass(frozen=True)
class ExecKey:
    """One entry of the key list."""

    key: str
    runs: str = COMMAND
    bang: bool = False
    driver: str | None = None
    fires_on_its_own: bool = False
    override: Override = Override()

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
        if self.runs == ABSOLUTE_PATH:
            return text if os.path.isabs(os.path.expanduser(text)) else None
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
                   fires_on_its_own=bool(raw.get("fires_on_its_own", False)),
                   override=_override(key, raw.get("override") or {}))


def _override(key: str, raw: dict) -> Override:
    """Read one entry's `override`. Takes the entry's key and the mapping. Returns it, or raises
    ValueError on a malformed one."""
    if not isinstance(raw, dict) or set(raw) - _OVERRIDE_FIELDS:
        raise ValueError(f"git exec key {key}: malformed `override` {raw!r}")
    if sum(raw.get(name) is not None for name in ("setting", "environment", "reset")) > 1:
        raise ValueError(f"git exec key {key}: `override` names more than one way")
    texts = {name: raw.get(name) for name in ("setting", "environment", "reset", "value")}
    if any(text is not None and not isinstance(text, str) for text in texts.values()):
        raise ValueError(f"git exec key {key}: `override` values are text")
    return Override(setting=texts["setting"], environment=texts["environment"],
                    value=texts["value"] or "", reset=texts["reset"],
                    refuse=bool(raw.get("refuse", False)))


@functools.lru_cache(maxsize=None)
def exec_keys(path: Path = KEYS_FILE) -> tuple[ExecKey, ...]:
    """Load the key list. Takes the file (default: the shipped list). Returns its entries in file
    order; raises ValueError on a malformed file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return tuple(_entry(raw) for raw in data.get("keys") or ())


@dataclass(frozen=True)
class RunsNothing:
    """A key whose name looks like a program's but whose value git never runs from a folder's
    settings, and why."""

    key: str
    why: str

    def matches(self, key: str) -> bool:
        """Say whether a listed key is this entry. Takes the listed key."""
        return fnmatchcase(key.lower(), self.key)


@functools.lru_cache(maxsize=None)
def runs_nothing(path: Path = KEYS_FILE) -> tuple[RunsNothing, ...]:
    """Load the keys that run nothing. Takes the file (default: the shipped list). Returns its
    entries in file order, or raises ValueError on a malformed file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    found = []
    for raw in data.get("runs_nothing") or ():
        key, why = (raw.get("key"), raw.get("why")) if isinstance(raw, dict) else (None, None)
        if not isinstance(key, str) or key != key.lower() or not isinstance(why, str) or not why:
            raise ValueError(f"git runs-nothing entry needs a lowercase `key` and a `why`: {raw!r}")
        found.append(RunsNothing(key, why))
    return tuple(found)


@functools.lru_cache(maxsize=None)
def always_set(path: Path = KEYS_FILE) -> tuple[tuple[str, str], ...]:
    """Load the settings every command saw does not check runs with. Takes the file (default: the
    shipped list). Returns each key with its value, or raises ValueError on a malformed file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    found = []
    for raw in data.get("always_set") or ():
        key, value, why = (raw.get("key"), raw.get("value"), raw.get("why")) if isinstance(raw, dict) else (None,) * 3
        if not isinstance(key, str) or not isinstance(value, str) or not isinstance(why, str) or not why:
            raise ValueError(f"git always-set entry needs a `key`, a `value` and a `why`: {raw!r}")
        found.append((key, value))
    return tuple(found)


@functools.lru_cache(maxsize=4096)
def rule_for(key: str) -> ExecKey | None:
    """Look up a key as git lists it. Returns its entry, or None when git does not execute it."""
    return next((rule for rule in exec_keys() if rule.matches(key)), None)
