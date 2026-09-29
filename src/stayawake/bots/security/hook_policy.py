#!/usr/bin/env python3
"""The policy a git hook scans under: saw's packaged signatures and the operator's own allowlist,
never the configuration of the repository being scanned."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.utils.config import load_yaml
from stayawake.bots.security.service.config import _options
from stayawake.bots.security.signatures import load_signatures


@dataclass(frozen=True)
class HookPolicy:
    """The options, signatures and allowlist one hook run scans with."""

    opts: object
    signatures: dict
    allowlist: list


def operator_policy(config_path: str | None) -> HookPolicy:
    """Read the policy a hook scans under. Takes the operator's config path, recorded at install.
    Returns the policy; with no config, the packaged signatures and an empty allowlist."""
    cfg = load_yaml(config_path) if (config_path and Path(config_path).is_file()) else {}
    settings = cfg.get("settings", {}) if isinstance(cfg, dict) else {}
    allowlist = (cfg.get("allowlist") if isinstance(cfg, dict) else None) or []
    return HookPolicy(_options(settings), load_signatures(settings.get("signatures_path")), allowlist)
