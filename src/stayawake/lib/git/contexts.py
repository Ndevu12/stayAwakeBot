#!/usr/bin/env python3
"""Who a git command runs on behalf of, and so what configuration and environment it may see.

- `UNTRUSTED` — any repository saw did not create. Only driver-free subcommands run (see
  `allowlist`), with every command-executing key overridden and the operator's global and system
  configuration hidden.
- `SAW_OWNED` — a repository this process created (`owned.own`). Any local subcommand, same overrides
  and isolation.
- `OPERATOR_PUSH` — push, fetch, ls-remote and clone, from no repository or a saw-owned one, with the
  operator's own configuration (credentials, signing, ssh, proxies) and only https/ssh transports.
- `OPERATOR_CONFIG` — reading or writing the operator's own configuration, and asking their credential
  helper, from no repository at all.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils import scratch

GIT_LOCATION_VARS = frozenset({
    "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES", "GIT_PREFIX",
})
GIT_CONFIG_INJECTION_PREFIXES = ("GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_",
                                 "GIT_CONFIG_VALUE_")
_ISOLATION_VARS = ("GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")

OPERATOR_TRANSPORTS = ("https", "ssh")
_STORED_VIEW = {"GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.path.join(os.devnull, "grafts"),
                "GIT_NO_LAZY_FETCH": "1"}

_NO_EXECUTION = (
    ("core.fsmonitor", "false"),
    ("diff.external", ""),
    ("core.pager", "cat"),
    ("core.editor", "false"),
    ("sequence.editor", "false"),
    ("protocol.allow", "never"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("credential.helper", ""),
    ("log.showSignature", "false"),
    ("log.mailmap", "false"),
    ("commit.gpgSign", "false"),
    ("tag.gpgSign", "false"),
    ("gpg.program", "false"),
    ("gpg.openpgp.program", "false"),
    ("gpg.x509.program", "false"),
    ("gpg.ssh.program", "false"),
    ("gpg.ssh.defaultKeyCommand", "false"),
    ("core.sshCommand", "false"),
    ("core.askPass", "false"),
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
)

_OPERATOR_NETWORK = (
    ("core.fsmonitor", "false"),
    ("core.pager", "cat"),
    ("core.editor", "false"),
    ("protocol.allow", "never"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("log.showSignature", "false"),
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
)

_OPERATOR_LOCAL = (
    ("core.fsmonitor", "false"),
    ("core.pager", "cat"),
    ("core.editor", "false"),
    ("protocol.allow", "never"),
)


@dataclass(frozen=True)
class Context:
    """What a git command may see. `overrides` are `-c` pairs placed before the caller's arguments;
    `operator_scopes` keeps the operator's global/system configuration and inherited `GIT_*`;
    `repository` is "any", "owned-or-none" or "none"; `literal_pathspecs` disables pathspec magic."""

    name: str
    overrides: tuple[tuple[str, str], ...]
    operator_scopes: bool
    repository: str
    literal_pathspecs: bool

    def __repr__(self) -> str:
        return self.name


UNTRUSTED = Context("UNTRUSTED", _NO_EXECUTION, False, "any", True)
SAW_OWNED = Context("SAW_OWNED", _NO_EXECUTION, False, "owned-or-none", True)
OPERATOR_PUSH = Context("OPERATOR_PUSH", _OPERATOR_NETWORK, True, "owned-or-none", False)
OPERATOR_CONFIG = Context("OPERATOR_CONFIG", _OPERATOR_LOCAL, True, "none", False)

KEYS_A_CALLER_MAY_NOT_SET = frozenset({
    "core.hookspath", "core.fsmonitor", "diff.external", "core.pager", "core.editor",
    "sequence.editor", "protocol.allow", "credential.helper", "core.askpass", "core.sshcommand",
    "gc.auto", "maintenance.auto", "submodule.recurse", "fetch.recursesubmodules",
})

_hooks_dir: Path | None = None
_neutral_dir: Path | None = None


def empty_hooks_dir() -> Path:
    """A saw-owned empty directory for `core.hooksPath`. Returns it, recreating it if released."""
    global _hooks_dir
    if _hooks_dir is None or not _hooks_dir.is_dir():
        _hooks_dir = scratch.new_dir("git runs no hooks")
    return _hooks_dir


def neutral_dir() -> Path:
    """A saw-owned empty directory that repository-less git runs from. Returns it, recreating it if
    released."""
    global _neutral_dir
    if _neutral_dir is None or not _neutral_dir.is_dir():
        _neutral_dir = scratch.new_dir("git outside any repository")
    return _neutral_dir


def config_prefix(context: Context) -> list[str]:
    """The `-c` arguments and global options `context` places before the caller's arguments."""
    out = ["-c", f"core.hooksPath={empty_hooks_dir()}"]
    for key, value in context.overrides:
        out += ["-c", f"{key}={value}"]
    if context is OPERATOR_PUSH:
        for transport in OPERATOR_TRANSPORTS:
            out += ["-c", f"protocol.{transport}.allow=always"]
    if context.literal_pathspecs:
        out.append("--literal-pathspecs")
    return out


def _injects_config(key: str) -> bool:
    return key == "GIT_CONFIG" or key.startswith(GIT_CONFIG_INJECTION_PREFIXES)


def child_env(context: Context, env: dict | None, *, operator_scopes: bool | None = None,
              repository_less: bool = False) -> dict:
    """The environment git runs in. Takes the context, the caller's environment (a whole environment,
    as `os.environ` is) and whether the command reads the operator's configuration. Returns it.

    A `GIT_*` variable the caller set or changed is kept; one merely inherited is kept only where the
    operator's scopes are, and never when it relocates the repository or injects configuration."""
    scopes = context.operator_scopes if operator_scopes is None else operator_scopes
    inherited = os.environ
    source = inherited if env is None else env
    out: dict[str, str] = {}
    for key, value in source.items():
        if not key.startswith("GIT_"):
            out[key] = value
            continue
        explicit = env is not None and inherited.get(key) != value
        if explicit and not _injects_config(key) and key not in _ISOLATION_VARS:
            out[key] = value
        elif scopes and key not in GIT_LOCATION_VARS and not _injects_config(key):
            out[key] = value
    if not scopes:
        for key in _ISOLATION_VARS:
            out.pop(key, None)
        out["GIT_CONFIG_NOSYSTEM"] = "1"
        out["GIT_CONFIG_GLOBAL"] = os.devnull
    out["GIT_TERMINAL_PROMPT"] = "0"
    out["GIT_ALLOW_PROTOCOL"] = ":".join(OPERATOR_TRANSPORTS) if context is OPERATOR_PUSH else ""
    out.update(_STORED_VIEW)
    if repository_less:
        out["GIT_CEILING_DIRECTORIES"] = str(neutral_dir().parent)
    return out
