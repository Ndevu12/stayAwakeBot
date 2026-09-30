#!/usr/bin/env python3
"""Where every command gets its config."""
from __future__ import annotations

import sys
from pathlib import Path

from stayawake.utils.config import load_yaml
from stayawake.bots.security.resolution import DEFAULT_CONFIG


def _announce(source: str | Path, cfg: dict) -> None:
    """Say which config is in force and how many allowlist rules it holds. Takes the source and the
    config."""
    rules = cfg.get("allowlist") or []
    if isinstance(rules, list) and rules:
        print(f"config: {source} ({len(rules)} allowlist rule(s) in effect)", file=sys.stderr)


ALLOWLIST_SHAPE = "config `allowlist` must be a list of {signature, path_glob} mappings."


def allowlist_ok(cfg: dict) -> bool:
    """Tell whether a config's allowlist can be applied. Takes the config. Returns True when it is a
    list of mappings."""
    rules = cfg.get("allowlist") or []
    return isinstance(rules, list) and all(isinstance(rule, dict) for rule in rules)


def _installed_with() -> str | None:
    """Return the config the operator installed saw's hooks with, if any."""
    from stayawake.bots.security import hookscript
    recorded = hookscript.installed()
    return recorded[1] if recorded and recorded[1] else None


def resolve_config(config_path: str | None, *, act_on: str = "the current repository",
                   targets: list[str] | None = None) -> dict | None:
    """Read the config for this run. Takes the config named on the command line, what the run acts
    on, and its targets. Returns the config: the one named, else the one saw's hooks were installed
    with, else empty. Returns None when a named config does not exist or cannot be applied. A config
    file that merely sits in the working directory is not read."""
    if config_path is None:
        if Path(DEFAULT_CONFIG).is_file():
            print(f"note: {DEFAULT_CONFIG} in this directory was not read; saw reads only the config "
                  "you name with -c, or the one you installed its hooks with.", file=sys.stderr)
        config_path = _installed_with()
        if config_path is None or not Path(config_path).is_file():
            return {}
    elif not Path(config_path).is_file():
        print(f"error: config '{config_path}' not found. Pass --config <path>, or omit it to act on "
              f"{act_on}.", file=sys.stderr)
        return None
    cfg = load_yaml(config_path) or {}
    if not isinstance(cfg, dict) or not allowlist_ok(cfg):
        print(f"error: {ALLOWLIST_SHAPE}", file=sys.stderr)
        return None
    _announce(config_path, cfg)
    return cfg
