#!/usr/bin/env python3
"""OSV record parsing + malicious classification (#1120).

Every knowledge source we consume — OpenSSF malicious-packages, the GitHub Advisory Database,
and OSV.dev's per-ecosystem exports — publishes the **same** OSV JSON schema, so there is one
parser here, not three. `parse_osv_record` normalizes a raw OSV object into the minimal shape
the corpus matches on; `is_malicious` classifies a record as malware (as opposed to an ordinary
CVE) using structured signals only — never free-text — so the classification stays honest.

A record matches either by an **explicit affected-version list** (`affected[].versions`) or by an
affected **range** (`affected[].ranges[]`, evaluated by the per-ecosystem comparators in #1124).
Pure and I/O-free; all reading/caching lives in `db.py`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Embedded Malicious Code — the CWE GitHub tags on malware advisories; a strong, structured
# "this is malware, not a vuln" signal that complements the OpenSSF `MAL-` id convention.
_MALWARE_CWE = "CWE-506"


@dataclass(frozen=True)
class OsvRange:
    """One affected range: its comparator `type` (SEMVER | ECOSYSTEM | GIT) and its ordered
    `events` (`introduced`/`fixed`/`last_affected` → version), which define the affected intervals."""

    type: str
    events: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class OsvAffected:
    """One `affected` package entry: its explicit versions and/or version ranges."""

    ecosystem: str
    name: str
    versions: frozenset[str]
    ranges: tuple[OsvRange, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class OsvRecord:
    """A normalized OSV advisory: its id, cross-source aliases, malware flag, and the packages
    (with affected versions/ranges) it names."""

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


def _parse_ranges(entry: dict[str, Any]) -> tuple[OsvRange, ...]:
    out: list[OsvRange] = []
    for r in (entry.get("ranges", []) or []):
        if not isinstance(r, dict):
            continue
        rtype = str(r.get("type", "")).strip().upper()
        events: list[tuple[str, str]] = []
        for ev in (r.get("events", []) or []):
            if isinstance(ev, dict):
                for kind in ("introduced", "fixed", "last_affected"):
                    if kind in ev:
                        events.append((kind, str(ev[kind])))
        if rtype and events:
            out.append(OsvRange(rtype, tuple(events)))
    return tuple(out)


def parse_osv_record(rec: dict[str, Any]) -> OsvRecord | None:
    """Normalize one raw OSV object → `OsvRecord`, or None when it carries nothing matchable
    (no id, or no `affected` entry with either explicit versions or a range)."""
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
        ranges = _parse_ranges(entry)
        if name and (versions or ranges):
            affected.append(OsvAffected(ecosystem, name, versions, ranges))
    if not affected:
        return None
    return OsvRecord(id=rid, aliases=aliases, malicious=is_malicious(rec), affected=tuple(affected))
