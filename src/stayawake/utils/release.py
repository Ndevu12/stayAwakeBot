#!/usr/bin/env python3
"""The saw release this code belongs to, or `0+unknown` from a source tree."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _distribution_version

try:
    RELEASE = _distribution_version("stayawakebot")
except PackageNotFoundError:
    RELEASE = "0+unknown"
