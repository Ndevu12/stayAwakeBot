#!/usr/bin/env python3
"""What a coding agent on this machine may run without asking.

An agent opens directories as its normal operation and runs unattended. Where it holds a standing
approval, a proposal becomes an action with nobody present to see it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import riskycommands
from .models import HygieneIssue, could_not_read

JSON, TOML = "json", "toml"

APPROVES_RISKY_ID = "agent-approves-risky-commands"
RUNS_WITHOUT_ASKING_ID = "agent-runs-without-asking"
AGENTS_NOT_EXAMINED_ID = "agents-not-examined"

_DOCS = ("https://github.com/Ndevu12/stayAwakeBot/blob/main/docs/how-to/audit-a-machine.md"
         "#what-a-clean-audit-does-and-does-not-mean")

_KNOWN = (
    ("Claude Code", "~/.claude/settings.json", JSON),
    ("Claude Code", "~/.claude/settings.local.json", JSON),
    ("Cursor", "~/.cursor/cli-config.json", JSON),
    ("Codex", "~/.codex/config.toml", TOML),
)

_ASKS_NOTHING = frozenset({"never", "none", "off", "false", "auto", "full-auto", "yolo",
                           "danger-full-access", "bypasspermissions", "disabled"})

_APPROVAL_KEYS = ("approvalmode", "approval_policy", "approval_mode", "defaultmode")

_SANDBOX_KEYS = ("sandbox_mode", "sandbox")

_MATCHES_ANYTHING = frozenset({"*", "**", ":*", "bash", "bash(*)", "bash(*:*)", "all", ".*"})


@dataclass(frozen=True)
class Agent:
    """One coding agent on this machine, and the file holding what it may do unasked."""

    name: str
    config: Path
    kind: str


@dataclass
class Standing:
    """What one agent's configuration grants without asking."""

    agent: Agent
    approved: list[str] = field(default_factory=list)
    asks_nothing: bool = False
    unsandboxed: bool = False

    @property
    def risky(self) -> list[str]:
        """The risky commands this agent may run unasked."""
        named: list[str] = []
        for rule in self.approved:
            for name in riskycommands.named_in(rule):
                if name not in named:
                    named.append(name)
        return named

    @property
    def approves_anything(self) -> bool:
        return any(r.strip().lower() in _MATCHES_ANYTHING for r in self.approved)


def _values_under(data, keys: tuple[str, ...]) -> list[str]:
    """Every value any of `keys` holds, at any depth, as lower-case text."""
    out: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in keys:
                out.append(str(value.get("mode", value) if isinstance(value, dict)
                               else value).lower())
            out += _values_under(value, keys)
    elif isinstance(data, list):
        for item in data:
            out += _values_under(item, keys)
    return out


def _allow_rules(data) -> list[str]:
    """Every standing allow rule, at any depth."""
    out: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() == "allow" and isinstance(value, list):
                out += [str(v) for v in value]
            out += _allow_rules(value)
    elif isinstance(data, list):
        for item in data:
            out += _allow_rules(item)
    return out


def _read_toml_pairs(text: str) -> dict:
    """The top-level `key = value` pairs of a TOML file, as strings.

    Only what this grades: a scalar an operator sets to turn approval or the sandbox off.
    """
    pairs = {}
    for line in text.splitlines():
        m = re.match(r'\s*([A-Za-z_][\w.]*)\s*=\s*"?([^"#]*)"?', line)
        if m:
            pairs[m.group(1)] = m.group(2).strip()
    return pairs


def _standing_of(agent: Agent, text: str) -> Standing:
    """Grade one agent's configuration text."""
    if agent.kind == TOML:
        pairs = _read_toml_pairs(text)
        data = {k: v for k, v in pairs.items()}
    else:
        data = json.loads(text)
    approval = _values_under(data, _APPROVAL_KEYS)
    sandbox = _values_under(data, _SANDBOX_KEYS)
    return Standing(
        agent=agent,
        approved=_allow_rules(data),
        asks_nothing=any(v in _ASKS_NOTHING for v in approval),
        unsandboxed=any(v in _ASKS_NOTHING for v in sandbox),
    )


def installed(known=_KNOWN) -> tuple[list[Agent], list[Path]]:
    """Every agent configuration on this machine, and the ones that could not be read."""
    found: list[Agent] = []
    unreadable: list[Path] = []
    for name, where, kind in known:
        path = Path(where).expanduser()
        try:
            if not path.is_file():
                continue
        except OSError:
            unreadable.append(path)
            continue
        found.append(Agent(name, path, kind))
    return found, unreadable


def standings(find=installed) -> tuple[list[Standing], list[Path]]:
    """What each agent on this machine grants, and what could not be read."""
    agents, unreadable = find()
    out: list[Standing] = []
    for agent in agents:
        try:
            text = agent.config.read_text(encoding="utf-8")
        except (OSError, ValueError):
            unreadable.append(agent.config)
            continue
        try:
            out.append(_standing_of(agent, text))
        except ValueError:
            unreadable.append(agent.config)
    return out, unreadable


def check_agents(find=installed) -> list[HygieneIssue]:
    """Grade what every coding agent on this machine may do without asking."""
    held, unreadable = standings(find)
    issues: list[HygieneIssue] = []
    unasked = sorted({s.agent.name for s in held if s.asks_nothing or s.approves_anything})
    if unasked:
        issues.append(HygieneIssue(
            id=RUNS_WITHOUT_ASKING_ID,
            severity="warning",
            title=f"{', '.join(unasked)} runs commands without asking",
            detail="An agent here has no approval step, so anything it proposes runs unattended.",
            remediation="Run `saw harden`.", reference=_DOCS,
        ))
    risky = sorted({name for s in held for name in s.risky})
    if risky:
        issues.append(HygieneIssue(
            id=APPROVES_RISKY_ID,
            severity="warning",
            title="An agent here may run risky commands without asking",
            detail=f"Standing approval covers {', '.join(risky)}.",
            remediation="Run `saw harden`.", reference=_DOCS,
        ))
    if unreadable:
        issues.append(could_not_read(unreadable))
    return issues
