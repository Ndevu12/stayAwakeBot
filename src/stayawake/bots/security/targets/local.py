#!/usr/bin/env python3
"""A repository already present on disk."""
from __future__ import annotations

from stayawake.bots.security.targets.base import Target


class LocalRepoTarget(Target):
    source = "local"
