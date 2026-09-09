#!/usr/bin/env python3
"""Take back what a coding agent on this machine may run without asking.

A standing approval for a risky command is withdrawn and an approval step that was turned off is
put back. An approval the operator granted that is not risky is left exactly as it is.
"""
from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.bots.security.hygiene import agents, riskycommands
from stayawake.utils import atomicwrite, env

WITHDRAWN, ALREADY_SAFE, NOT_WRITTEN = "withdrawn", "already-safe", "not-written"

_ASKS_AGAIN = {"approvalmode": "allowlist", "approval_policy": "on-request",
               "approval_mode": "on-request", "defaultmode": "default"}

_SANDBOXED = {"sandbox_mode": "workspace-write", "sandbox": "workspace-write"}


@dataclass(frozen=True)
class Outcome:
    """What one pass did to one agent's configuration."""

    name: str
    path: Path
    state: str
    detail: str = ""


@dataclass
class Correcting:
    """What settling this machine's agents did."""

    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def settled(self) -> bool:
        return not [o for o in self.outcomes if o.state == NOT_WRITTEN]

    @property
    def changed(self) -> bool:
        return any(o.state == WITHDRAWN for o in self.outcomes)


@dataclass
class TakingBack:
    """What restoring the agent configuration did."""

    restored: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    unreadable_record: bool = False

    @property
    def done(self) -> bool:
        return not self.failed and not self.unreadable_record


def record_path() -> Path:
    """Where saw records what it withdrew, so a later run can put it back."""
    return Path(env.xdg_state_home()) / "saw" / "agent-approvals.json"


def _read(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as handle:
        return handle.read()


def _mode_of(path: Path) -> int:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return 0o600


def _remembered(path: Path) -> tuple[list[dict], bool]:
    """What saw withdrew and has not put back, and whether that answer is trustworthy."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], True
    except (OSError, ValueError):
        return [], False
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return [], False
    return [e for e in entries if isinstance(e, dict)], True


def _remember(entries: list[dict], path: Path) -> bool:
    held, readable = _remembered(path)
    if not readable:
        return False
    for entry in entries:
        if entry not in held:
            held.append(entry)
    return atomicwrite.replace(path, json.dumps({"version": 1, "entries": held}))


def _without(text: str, rule: str) -> str | None:
    """`text` with the standing rule `rule` gone from its list, or None when it is not there once."""
    quoted = re.escape(json.dumps(rule))
    for shape in (r",\s*" + quoted, quoted + r"\s*,\s*", r"\s*" + quoted):
        pattern = re.compile(shape)
        if len(pattern.findall(text)) == 1:
            return pattern.sub("", text, count=1)
    return None


def _set_scalar(text: str, key: str, value: str) -> str | None:
    """`text` with `key` set to `value`, in JSON or TOML, or None when it is not there once."""
    pattern = re.compile(r'("?' + re.escape(key) + r'"?\s*[:=]\s*)"[^"]*"')
    if len(pattern.findall(text)) != 1:
        return None
    return pattern.sub(lambda m: m.group(1) + json.dumps(value), text, count=1)


def _still_holds(before: str, after: str, agent: agents.Agent, gone: list[str],
                 set_to: dict) -> bool:
    """Whether `after` is `before` with exactly those rules gone and those keys set."""
    try:
        was = agents._standing_of(agent, before)
        now = agents._standing_of(agent, after)
    except Exception:
        return False
    if set(was.approved) - set(now.approved) != set(gone):
        return False
    if set(now.approved) - set(was.approved):
        return False
    for key, value in set_to.items():
        if value.lower() not in [v.lower() for v in
                                 agents._values_under(_parsed(agent, after), (key,))]:
            return False
    return True


def _parsed(agent: agents.Agent, text: str):
    if agent.kind == agents.TOML:
        return agents._read_toml_pairs(text)
    return json.loads(text)


def _safer_value(key: str) -> str | None:
    return _ASKS_AGAIN.get(key) or _SANDBOXED.get(key)


def settle(find=agents.installed, write=None, record: Path | None = None,
           remember=None) -> Correcting:
    """Withdraw every risky standing approval on this machine, and put back a missing approval step.

    Returns one outcome per agent. An approval that is not risky is never touched.
    """
    write = write or atomicwrite.replace
    remember = _remember if remember is None else remember
    where = record or record_path()
    held, _unreadable = agents.standings(find)
    out = Correcting()
    for standing in held:
        agent = standing.agent
        try:
            text = before = _read(agent.config)
        except (OSError, ValueError):
            out.outcomes.append(Outcome(agent.name, agent.config, NOT_WRITTEN,
                                        "its configuration could not be read"))
            continue
        gone = [rule for rule in standing.approved
                if riskycommands.named_in(rule) or rule.strip().lower() in agents._MATCHES_ANYTHING]
        set_to: dict[str, str] = {}
        wanted = list(agents._APPROVAL_KEYS) if standing.asks_nothing else []
        if standing.unsandboxed and standing.asks_nothing:
            wanted += list(agents._SANDBOX_KEYS)
        for key in wanted:
            safer = _safer_value(key)
            if safer and _set_scalar(text, key, safer) is not None:
                set_to[key] = safer
        if not gone and not set_to:
            out.outcomes.append(Outcome(agent.name, agent.config, ALREADY_SAFE))
            continue
        failed = False
        for rule in gone:
            stepped = _without(text, rule)
            if stepped is None:
                failed = True
                break
            text = stepped
        for key, value in set_to.items():
            stepped = _set_scalar(text, key, value)
            if stepped is None:
                failed = True
                break
            text = stepped
        if failed or not _still_holds(before, text, agent, gone, set_to):
            out.outcomes.append(Outcome(agent.name, agent.config, NOT_WRITTEN,
                                        "the change did not read back as exactly that change"))
            continue
        try:
            if _read(agent.config) != before:
                raise OSError
        except (OSError, ValueError):
            out.outcomes.append(Outcome(agent.name, agent.config, NOT_WRITTEN,
                                        "its configuration changed while this was reading it"))
            continue
        if not write(agent.config, text, mode=_mode_of(agent.config)):
            out.outcomes.append(Outcome(agent.name, agent.config, NOT_WRITTEN,
                                        "the change could not be written"))
            continue
        remember([{"path": str(agent.config), "kind": agent.kind, "rules": gone,
                   "keys": {k: _was_scalar(before, k) for k in set_to}}], where)
        out.outcomes.append(Outcome(agent.name, agent.config, WITHDRAWN,
                                    ", ".join(gone + sorted(set_to))))
    return out


def _was_scalar(text: str, key: str) -> str | None:
    m = re.search(r'"?' + re.escape(key) + r'"?\s*[:=]\s*"([^"]*)"', text)
    return m.group(1) if m else None


def _put_rules_back(text: str, rules: list[str]) -> str | None:
    """`text` with each rule added back to the first allow list it holds."""
    for rule in rules:
        m = re.search(r'("allow"\s*:\s*\[)', text)
        if m is None:
            return None
        text = text[:m.end()] + f"\n    {json.dumps(rule)}," + text[m.end():]
    return text


def take_back(record: Path | None = None, write=None) -> TakingBack:
    """Put back every standing approval saw withdrew."""
    write = write or atomicwrite.replace
    where = record or record_path()
    out = TakingBack()
    entries, readable = _remembered(where)
    if not readable:
        out.unreadable_record = True
        return out
    left: list[dict] = []
    for entry in entries:
        path = entry.get("path")
        if not isinstance(path, str):
            continue
        rules = [str(r) for r in entry.get("rules", []) if isinstance(r, str)]
        keys = entry.get("keys") if isinstance(entry.get("keys"), dict) else {}
        try:
            text = _read(Path(path))
        except (OSError, ValueError):
            out.failed.append(path)
            left.append(entry)
            continue
        stepped = _put_rules_back(text, rules) if rules else text
        for key, value in keys.items():
            if stepped is None or value is None:
                continue
            stepped = _set_scalar(stepped, key, value)
        if stepped is None or not write(Path(path), stepped, mode=_mode_of(Path(path))):
            out.failed.append(path)
            left.append(entry)
            continue
        out.restored.append(path)
    if not atomicwrite.replace(where, json.dumps({"version": 1, "entries": left})):
        out.unreadable_record = True
    return out
