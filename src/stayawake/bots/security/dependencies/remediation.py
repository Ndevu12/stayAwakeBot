#!/usr/bin/env python3
"""Actionable remediation for a flagged dependency.

The scanner already knows *what* is wrong (advisory X affects package Y) and — for a bounded CVE — the
first patched version (`AdvisoryMatch.fixed`). This module turns that into advice a reader can act on:
"upgrade Y to Z", the ecosystem's install command, and a link to the advisory. Pure and offline — it
only FORMATS what the corpus already holds; it never runs a package manager or reaches the network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from stayawake.bots.security.dependencies.ecosystems import canonical_ecosystem
from stayawake.utils import textsafe

REMOVE = "remove"
UPGRADE = "upgrade"

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


@dataclass(frozen=True)
class DependencyFix:
    """What to do about one flagged dependency: the sentence to show, and which action it is."""

    advice: str
    action: str


@dataclass(frozen=True)
class DependencyAction:
    """One line of advice, with the advisory to read for it."""

    advice: str
    reference: str | None = None


@dataclass(frozen=True)
class DependencyActions:
    """The advice for one scan, split by action."""

    remove: tuple[DependencyAction, ...] = ()
    upgrade: tuple[DependencyAction, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.remove or self.upgrade)


def vulnerability_fix(ecosystem: str, name: str, fixed_version: str | None) -> DependencyFix:
    """The fix for an ordinary CVE on a dependency. Takes the ecosystem, the package name and the
    first patched version, or None when the advisory publishes no fix. Returns a `DependencyFix`:
    an upgrade to that version with the ecosystem's command, or a removal when no version is
    published to move to."""
    if fixed_version:
        base = f"Upgrade {name} to {fixed_version} or later (first patched version)."
        cmd = upgrade_command(ecosystem, name, fixed_version)
        return DependencyFix(f"{base}  {cmd}" if cmd else f"{base}  Bump it in your manifest and "
                             "reinstall.", UPGRADE)
    return DependencyFix(
        f"No patched version is published for this advisory — remove or replace {name}, or pin it "
        "to a version outside the affected range.", REMOVE)


def malware_fix(name: str) -> DependencyFix:
    """The fix for a known-malicious dependency. Takes the package name. Returns a `DependencyFix`
    that removes it, because no later version of it is a safe one."""
    return DependencyFix(
        f"Remove {name} now — it is a known-malicious package, so upgrading does not help. Purge it "
        "from your lockfile and installed tree, then rotate any credentials it could have read.",
        REMOVE)


def external_advisory_fix(name: str, advisory_id: str, tool: str) -> DependencyFix:
    """The fix for an advisory an external auditor raised. Takes the package name, the advisory id
    and the auditor that reported it. Returns a `DependencyFix` that upgrades, naming the advisory
    to read rather than a version, which the auditor does not report."""
    return DependencyFix(f"Upgrade {name} to a release that resolves {advisory_id} (see the "
                         f"advisory), then re-run {tool}.", UPGRADE)


def _field(item, name: str):
    """One field of a finding, whether it arrives as a `Finding` or as its payload dict."""
    return item.get(name) if isinstance(item, dict) else getattr(item, name, None)


def dependency_actions(*groups) -> DependencyActions:
    """The advice to show an operator once per run. Takes any number of iterables of findings, as
    objects or as payload dicts. Returns a `DependencyActions`, empty when none of them carries
    advice; identical advice raised by several findings is carried once."""
    buckets: dict[str, dict[str, DependencyAction]] = {REMOVE: {}, UPGRADE: {}}
    for group in groups:
        for item in group:
            advice = _field(item, "fix_advice")
            bucket = buckets.get(_field(item, "dependency_action"))
            if advice and bucket is not None:
                bucket.setdefault(advice, DependencyAction(advice, _field(item, "reference")))
    return DependencyActions(remove=tuple(buckets[REMOVE].values()),
                             upgrade=tuple(buckets[UPGRADE].values()))


def _capped(actions: tuple[DependencyAction, ...], limit: int):
    """Takes the actions for one heading and the most a surface will show. Returns those to show
    and how many were left out."""
    return actions[:limit], max(0, len(actions) - limit)


def markdown_lines(actions: tuple[DependencyAction, ...], limit: int) -> list[str]:
    """Takes the actions under one heading and the most to show. Returns Markdown bullets, each
    carrying the command to run and the advisory to read."""
    shown, left_out = _capped(actions, limit)
    lines = [f"- {textsafe.code(a.advice)}" + (f" — {textsafe.code(a.reference)}" if a.reference else "")
             for a in shown]
    return lines + ([f"- \u2026and {left_out} more"] if left_out else [])


def plain_lines(actions: tuple[DependencyAction, ...], limit: int) -> list[str]:
    """Takes the actions under one heading and the most to show. Returns terminal lines, each
    carrying the command to run and the advisory to read."""
    shown, left_out = _capped(actions, limit)
    lines = [f"  \u2022 {textsafe.plain(a.advice, 400)}" +
             (f"\n    {textsafe.plain(a.reference)}" if a.reference else "") for a in shown]
    return lines + ([f"  \u2026and {left_out} more"] if left_out else [])
