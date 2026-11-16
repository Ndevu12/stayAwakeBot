#!/usr/bin/env python3
"""The saw release this code belongs to, taken from the installed distribution.

The release exists only as the git tag; the build writes it into the distribution's metadata.
A source tree with no installed distribution reports `0+unknown`.
"""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _distribution_version

try:
    RELEASE = _distribution_version("stayawakebot")
except PackageNotFoundError:
    RELEASE = "0+unknown"
