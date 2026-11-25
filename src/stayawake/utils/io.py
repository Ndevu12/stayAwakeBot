#!/usr/bin/env python3
"""Filesystem I/O (single responsibility: safe JSON read/write)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from stayawake.utils import atomicwrite, env, pathsafe


def resolve_writable_dir(preferred: str | Path, *, label: str = "reports") -> Path | None:
    """Make sure a folder can take reports. Takes the folder and what the reports are. Returns the
    folder, or none after saying on standard error why it cannot take them."""
    preferred = Path(preferred)
    try:
        atomicwrite.make_folder(preferred)
        check = preferred / ".saw-write-check"
        atomicwrite.replace(check, "")
        check.unlink()
        return preferred
    except pathsafe.RedirectedPath:
        why = "is reached through a link saw does not follow"
    except OSError as exc:
        why = f"cannot be written ({exc.strerror or exc})"
    print(f"error: {label} directory {preferred} {why}, so saw did not write the {label}.", file=sys.stderr)
    return None


def reports_dir_choice(explicit: str | Path | None = None, *,
                       settings_value: str | Path | None = None) -> str | Path | None:
    """The first source that ASKS for a report bundle, or None when none does.

    Precedence: `explicit` (a `--reports-dir` / call arg) → `STAYAWAKE_REPORTS_DIR` (the container
    image sets this to a writable, container-owned path) → `settings.reports_dir`.

    Separate from `resolve_reports_dir` so a caller can tell "nobody asked, write nothing" apart from
    "asked, and here is where". Conflating the two is what made the env and settings rungs
    unreachable: the only caller gated on its own `explicit` value, so the `or` chain could
    never reach past the first rung. Both functions read the precedence from HERE, so a consumer can
    never re-derive a different answer."""
    return explicit or env.get(env.STAYAWAKE_REPORTS_DIR) or settings_value or None


def resolve_reports_dir(explicit: str | Path | None = None, *,
                        settings_value: str | Path | None = None,
                        default: str | Path, label: str = "reports") -> Path | None:
    """Return the folder reports go to, ready for them. Takes the folder named on the command line,
    the one in the settings, the default and what the reports are. Returns the folder, or none when
    it cannot take them."""
    chosen = reports_dir_choice(explicit, settings_value=settings_value) or default
    return resolve_writable_dir(chosen, label=label)


def read_json(path: str | Path, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def write_json(path: str | Path, data: Any) -> None:
    """Atomic JSON write (temp file + rename) — never leaves a half-written file."""
    with atomicwrite.staged(Path(path), at_a_link=atomicwrite.REPLACE_A_LINK) as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
