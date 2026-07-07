#!/usr/bin/env python3
"""OSV record parsing + malicious classification (#1120).

Every knowledge source we consume — OpenSSF malicious-packages, the GitHub Advisory Database,
and OSV.dev's per-ecosystem exports — publishes the **same** OSV JSON schema, so there is one
parser here, not three. `parse_osv_record` normalizes a raw OSV object into the minimal shape
the corpus matches on; `is_malicious` classifies a record as malware (as opposed to an ordinary
CVE) using structured signals only — never free-text — so the classification stays honest.

Phase 1b matches on an advisory's **explicit affected-version list** only (`affected[].versions`).
Records whose `affected` entries carry only `ranges` (no explicit versions) are dropped here —
they are deferred to the per-ecosystem version-range comparators in #1124. Pure and I/O-free;
all reading/caching lives in `db.py`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Embedded Malicious Code — the CWE GitHub tags on malware advisories; a strong, structured
# "this is malware, not a vuln" signal that complements the OpenSSF `MAL-` id convention.
_MALWARE_CWE = "CWE-506"


@dataclass(frozen=True)
class OsvAffected:
    """One `affected` package entry, reduced to its explicit-version match surface."""

    ecosystem: str
    name: str
    versions: frozenset[str]


@dataclass(frozen=True)
class OsvRecord:
    """A normalized OSV advisory: its id, cross-source aliases, malware flag, and the packages
    (with explicit affected versions) it names."""

    id: str
    aliases: tuple[str, ...]
    malicious: bool
    affected: tuple[OsvAffected, ...]


def is_malicious(rec: dict[str, Any]) -> bool:
    """True if this OSV record describes malware (vs. an ordinary vulnerability).

    Structured signals only — no summary/details text matching (which would false-positive on a
    CVE that merely mentions "malicious"):
      * an `id` or `alias` in the OpenSSF `MAL-YYYY-NNNN` namespace, or
      * `database_specific.type == "malware"`, or
      * CWE-506 (Embedded Malicious Code) in `database_specific.cwe_ids`.
    """
    if str(rec.get("id", "")).startswith("MAL-"):
        return True
    for alias in rec.get("aliases", []) or []:
        if str(alias).startswith("MAL-"):
            return True
    ds = rec.get("database_specific")
    if isinstance(ds, dict):
        if str(ds.get("type", "")).lower() == "malware":
            return True
        cwes = ds.get("cwe_ids")
        if isinstance(cwes, list) and _MALWARE_CWE in cwes:
            return True
    return False


def parse_osv_record(rec: dict[str, Any]) -> OsvRecord | None:
    """Normalize one raw OSV object → `OsvRecord`, or None when it carries nothing matchable in
    this phase (no id, or no `affected` entry with an explicit version list)."""
    if not isinstance(rec, dict):
        return None
    rid = str(rec.get("id", "")).strip()
    if not rid:
        return None
    aliases = tuple(str(a) for a in (rec.get("aliases", []) or []) if isinstance(a, str))

    affected: list[OsvAffected] = []
    for entry in rec.get("affected", []) or []:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package") or {}
        ecosystem = str(pkg.get("ecosystem", "")).strip()
        name = str(pkg.get("name", "")).strip()
        versions = frozenset(v for v in (entry.get("versions", []) or []) if isinstance(v, str))
        if name and versions:          # ranges-only entries are deferred to #1124
            affected.append(OsvAffected(ecosystem, name, versions))
    if not affected:
        return None
    return OsvRecord(id=rid, aliases=aliases, malicious=is_malicious(rec), affected=tuple(affected))
