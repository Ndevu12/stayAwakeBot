#!/usr/bin/env python3
"""The operator's own git configuration, their global scope, read as data from no repository."""
from __future__ import annotations

import os
from pathlib import Path

from stayawake.lib.git.run import OPERATOR_CONFIG, run


def global_config() -> dict[str, str]:
    """Every key in the operator's global git config, lower-cased as git lists it, with the last
    value git would use. Empty when there is none or it cannot be read."""
    res = run(None, ["config", "--global", "--list", "-z"], context=OPERATOR_CONFIG)
    found: dict[str, str] = {}
    if res is None or res.returncode != 0:
        return found
    for entry in (res.stdout or "").split("\0"):
        key, newline, value = entry.partition("\n")
        if key:
            found[key] = value if newline else "true"
    return found


def global_bool(key: str) -> str:
    """`key` from the operator's global config as git spells a boolean (`true`/`false`), or ""
    when it is not set there."""
    res = run(None, ["config", "--global", "--type=bool", "--get", key], context=OPERATOR_CONFIG)
    return res.stdout.strip() if res is not None and res.returncode == 0 else ""


def global_excludes_file(config: dict[str, str] | None = None) -> Path | None:
    """The operator's global ignore file when it exists: `core.excludesfile`, else git's default
    under `$XDG_CONFIG_HOME/git/ignore`."""
    config = global_config() if config is None else config
    named = config.get("core.excludesfile", "")
    if named:
        candidate = Path(os.path.expanduser(named))
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        candidate = Path(xdg) / "git" / "ignore"
    return candidate if candidate.is_file() else None
