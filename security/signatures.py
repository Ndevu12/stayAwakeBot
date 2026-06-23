#!/usr/bin/env python3
"""Load and group the signature database (config/security_signatures.yml).

Single responsibility: turn the YAML data file into validated, matcher-grouped
signature dicts. No detection logic lives here.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from security.matchers import REGISTRY

_REQUIRED = ("id", "category", "severity", "matcher", "description")


def load_signatures(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Return {matcher_name: [signature, ...]} for matchers we actually have.

    Raises ValueError on a malformed DB so a typo fails loudly in CI rather than
    silently disabling detection.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    sigs = data.get("signatures", [])
    if not isinstance(sigs, list) or not sigs:
        raise ValueError(f"No signatures found in {path}")

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
        grouped[s["matcher"]].append(s)
    return dict(grouped)
