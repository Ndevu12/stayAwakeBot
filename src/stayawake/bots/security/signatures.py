#!/usr/bin/env python3
"""Load and group the signature database.

Single responsibility: turn the YAML data file into validated, matcher-grouped
signature dicts. The DEFAULT database ships inside the package
(`stayawake/bots/security/data/signatures.yml`) so an installed scanner is
self-contained; a caller may pass a path to override it. No detection logic here.
"""
from __future__ import annotations

from collections import defaultdict
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from stayawake.bots.security.matchers import REGISTRY
from stayawake.bots.security.models import CONFIDENCE_LEVELS

_REQUIRED = ("id", "category", "severity", "matcher", "description")


def _read_default() -> str:
    return files("stayawake.bots.security").joinpath("data/signatures.yml").read_text(encoding="utf-8")


def load_signatures(path: str | Path | None = None) -> dict[str, list[dict[str, Any]]]:
    """Return {matcher_name: [signature, ...]} for matchers we actually have.

    `path=None` (the default) loads the packaged signature DB. Raises ValueError on
    a malformed DB so a typo fails loudly in CI rather than silently disabling detection.
    """
    text = Path(path).read_text(encoding="utf-8") if path else _read_default()
    src = str(path) if path else "packaged default"
    data = yaml.safe_load(text) or {}
    sigs = data.get("signatures", [])
    if not isinstance(sigs, list) or not sigs:
        raise ValueError(f"No signatures found in {src}")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[str] = set()
    for s in sigs:
        missing = [k for k in _REQUIRED if k not in s]
        if missing:
            raise ValueError(f"Signature missing {missing}: {s.get('id', s)}")
        if s["id"] in seen:
            raise ValueError(f"Duplicate signature id: {s['id']}")
        seen.add(s["id"])
        if s["matcher"] not in REGISTRY:
            raise ValueError(f"Unknown matcher '{s['matcher']}' in signature {s['id']}")
        conf = s.get("confidence")
        if conf is not None and conf not in CONFIDENCE_LEVELS:
            raise ValueError(
                f"Signature {s['id']}: invalid confidence '{conf}' (use one of {CONFIDENCE_LEVELS})")
        grouped[s["matcher"]].append(s)
    return dict(grouped)
