#!/usr/bin/env python3
"""The policy a git hook scans under: saw's packaged signatures and the operator's own allowlist,
never the configuration of the repository being scanned."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.utils.config import load_yaml
from stayawake.bots.security.service.config import _options
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.config import ALLOWLIST_SHAPE, allowlist_ok


@dataclass(frozen=True)
class HookPolicy:
    """The options, signatures and allowlist one hook run scans with."""

    opts: object
    signatures: dict
    allowlist: list


def operator_policy(config_path: str | None) -> HookPolicy:
    """Read the policy a hook scans under. Takes the operator's config path, recorded at install.
    Returns the policy; with no config, the packaged signatures and an empty allowlist. Raises
    ValueError when the config's allowlist cannot be applied."""
    cfg = load_yaml(config_path) if (config_path and Path(config_path).is_file()) else {}
    if not isinstance(cfg, dict) or not allowlist_ok(cfg):
        raise ValueError(ALLOWLIST_SHAPE)
    settings = cfg.get("settings", {})
    allowlist = cfg.get("allowlist") or []
    return HookPolicy(_options(settings), load_signatures(settings.get("signatures_path")), allowlist)
