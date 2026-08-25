#!/usr/bin/env python3
"""Where every command gets its config — one resolution, one error message.

`scan`, `fix`, `discard`, `guard` and `hook` each had their own copy of this, and the sentence they
print was hand-copied between them. `scan`'s copy skipped the check its own docstring promised, so a
missing `--config` reached the user as a FileNotFoundError traceback.
"""
from __future__ import annotations

import sys
from pathlib import Path

from stayawake.utils.config import load_yaml
from stayawake.bots.security.resolution import DEFAULT_CONFIG


def _within_cwd(target: str | Path) -> bool:
    """True if `target` is the working directory or lives inside it."""
    try:
        Path(target).resolve().relative_to(Path.cwd().resolve())
        return True
    except (ValueError, OSError):
        return False


def _announce(source: str | Path, cfg: dict) -> None:
    """Name the config in force: an allowlist changes what a run reports, so it is never silent."""
    rules = cfg.get("allowlist") or []
    if isinstance(rules, list) and rules:
        print(f"config: {source} ({len(rules)} allowlist rule(s) in effect)", file=sys.stderr)


def resolve_config(config_path: str | None, *, act_on: str = "the current repository",
                   targets: list[str] | None = None) -> dict | None:
    """The config for this run, or None when a named config file does not exist.

    Omitting `--config` is never an error: a bare command works in any repository, using the default
    file only if it happens to be there. Naming a file that is not there always is.

    `DEFAULT_CONFIG` is relative, so it belongs to the working directory and is honoured only for
    targets inside it. Any other target must name its config; a scanned repo's own is never read.
    """
    if config_path is None:
        default = Path(DEFAULT_CONFIG)
        if not default.exists():
            return {}
        outside = [t for t in (targets or []) if not _within_cwd(t)]
        if outside:
            print(f"note: ignoring '{default}' — it belongs to the working directory, not to "
                  f"{', '.join(outside[:3])}. Pass --config to apply an allowlist to another "
                  f"target.", file=sys.stderr)
            return {}
        cfg = load_yaml(default) or {}
        _announce(default, cfg)
        return cfg
    if not Path(config_path).is_file():
        print(f"error: config '{config_path}' not found. Pass --config <path>, or omit it to act on "
              f"{act_on}.", file=sys.stderr)
        return None
    cfg = load_yaml(config_path) or {}
    _announce(config_path, cfg)
    return cfg
