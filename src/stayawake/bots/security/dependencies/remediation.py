#!/usr/bin/env python3
"""Actionable remediation for a flagged dependency (#1252).

The scanner already knows *what* is wrong (advisory X affects package Y) and — for a bounded CVE — the
first patched version (`AdvisoryMatch.fixed`). This module turns that into advice a reader can act on:
"upgrade Y to Z", the ecosystem's install command, and a link to the advisory. Pure and offline — it
only FORMATS what the corpus already holds; it never runs a package manager or reaches the network.
"""
from __future__ import annotations

import re

from stayawake.bots.security.dependencies.ecosystems import canonical_ecosystem

# A well-formed advisory id (CVE-…, GHSA-…, MAL-…, PYSEC-…, GO-…, RUSTSEC-…): a letter-led token of
# id-safe chars. Anything else — a bare number, or an id carrying whitespace/newlines/control chars
# (a hostile corpus record) — yields NO url rather than a broken or injected link (#1252).
_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{1,80}\Z")


# PURL type → how you install a specific version with that ecosystem's tool. Best-effort and
# deliberately simple (the exact incantation varies by project setup); the fixed VERSION is the
# load-bearing part, the command a convenience. Unknown ecosystems fall back to manifest guidance.
def _npm(n: str, v: str) -> str: return f"npm install {n}@{v}"
def _pypi(n: str, v: str) -> str: return f"pip install '{n}>={v}'"
def _gem(n: str, v: str) -> str: return f"bundle update {n} --conservative   # or: gem install {n} -v '>= {v}'"
def _cargo(n: str, v: str) -> str: return f"cargo update -p {n} --precise {v}"
def _composer(n: str, v: str) -> str: return f"composer require {n}:>={v}"
def _nuget(n: str, v: str) -> str: return f"dotnet add package {n} --version {v}"
def _maven(n: str, v: str) -> str: return f"set {n} to {v} in pom.xml, then rebuild"


def _golang(n: str, v: str) -> str:
    return f"go get {n}@{v if v.startswith('v') else 'v' + v}"     # Go module versions carry a `v` prefix


_UPGRADE = {"npm": _npm, "pypi": _pypi, "gem": _gem, "cargo": _cargo,
            "composer": _composer, "golang": _golang, "nuget": _nuget, "maven": _maven}


def upgrade_command(ecosystem: str, name: str, fixed_version: str) -> str | None:
    """The install-this-version command for `ecosystem` (best-effort), or None for an unknown one."""
    fn = _UPGRADE.get(canonical_ecosystem(ecosystem))
    return fn(name, fixed_version) if fn else None


def advisory_reference(osv_id: str | None, aliases: tuple[str, ...] = ()) -> str | None:
    """A URL a reader can open for the full advisory. Prefer a GitHub Advisory (GHSA — rich, carries
    fix metadata); else the OSV page for whatever id we have (OSV also resolves GHSA/CVE/MAL ids). Every
    id is gated by `_ID_RE`, so a malformed/hostile id yields no url rather than a broken/injected one."""
    ids = [i for i in ((osv_id,) + tuple(aliases)) if i and _ID_RE.match(i)]
    for i in ids:
        if i.startswith("GHSA-"):
            return f"https://github.com/advisories/{i}"
    if osv_id and _ID_RE.match(osv_id):
        return f"https://osv.dev/vulnerability/{osv_id}"
    for i in ids:
        if i.startswith("CVE-"):
            return f"https://osv.dev/vulnerability/{i}"
    return None


def vulnerability_fix(ecosystem: str, name: str, fixed_version: str | None) -> str:
    """Human remediation for an ordinary CVE on a dependency: upgrade to the first patched version
    (with the ecosystem's command when known), or — when no fix is published — remove/replace/pin."""
    if fixed_version:
        base = f"Upgrade {name} to {fixed_version} or later (first patched version)."
        cmd = upgrade_command(ecosystem, name, fixed_version)
        return f"{base}  {cmd}" if cmd else f"{base}  Bump it in your manifest and reinstall."
    return (f"No patched version is published for this advisory — remove or replace {name}, or pin it "
            "to a version outside the affected range.")


def malware_fix(name: str) -> str:
    """Human remediation for a KNOWN-MALICIOUS dependency — removal, not an upgrade."""
    return (f"Remove {name} now — it is a known-malicious package, so upgrading does not help. Purge it "
            "from your lockfile and installed tree, then rotate any credentials it could have read.")
