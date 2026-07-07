#!/usr/bin/env python3
"""Canonical ecosystem correspondence: our PURL type ↔ the OSV ecosystem/export name (#1123).

One source of truth shared by `db` (fetches the OSV export bucket for a PURL type) and `corpus`
(canonicalizes an advisory's OSV ecosystem back to the PURL type so a resolver's `Purl` matches).
PURL types follow the package-url spec (`cargo`, `golang`, `gem`, `composer`, …) and deliberately
differ from OSV's export names (`crates.io`, `Go`, `RubyGems`, `Packagist`, …) — this table is the
bridge, so the two representations can never drift out of sync.
"""
from __future__ import annotations

# PURL type → OSV ecosystem / export bucket name.
PURL_TO_OSV = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "golang": "Go",
    "gem": "RubyGems",
    "composer": "Packagist",
    "nuget": "NuGet",
    "maven": "Maven",
}

# OSV ecosystem name (lowercased) → PURL type — the inverse, for canonicalizing advisory records.
_OSV_TO_PURL = {osv.lower(): purl for purl, osv in PURL_TO_OSV.items()}


def canonical_ecosystem(name: str) -> str:
    """Map an OSV ecosystem string (or an already-canonical PURL type) to the PURL type. An OSV
    suffix (`Alpine:v3.16`) is dropped; an unknown ecosystem passes through lowercased so it still
    keys consistently on both sides of a match."""
    key = name.lower().split(":", 1)[0]
    return _OSV_TO_PURL.get(key, key)
