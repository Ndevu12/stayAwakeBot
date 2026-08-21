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


def resolve_config(config_path: str | None, *, act_on: str = "the current repository") -> dict | None:
    """The config for this run, or None when a named config file does not exist.

    Omitting `--config` is never an error: a bare command works in any repository, using the default
    file only if it happens to be there. Naming a file that is not there always is.
    """
    if config_path is None:
        default = Path(DEFAULT_CONFIG)
        return load_yaml(default) if default.exists() else {}
    if not Path(config_path).is_file():
        print(f"error: config '{config_path}' not found. Pass --config <path>, or omit it to act on "
              f"{act_on}.", file=sys.stderr)
        return None
    return load_yaml(config_path)
