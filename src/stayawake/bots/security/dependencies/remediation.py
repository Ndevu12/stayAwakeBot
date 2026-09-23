#!/usr/bin/env python3
"""Actionable remediation for a flagged dependency.

The scanner already knows *what* is wrong (advisory X affects package Y) and — for a bounded CVE — the
first patched version (`AdvisoryMatch.fixed`). This module turns that into advice a reader can act on:
"upgrade Y to Z", the ecosystem's install command, and a link to the advisory. Pure and offline — it
only FORMATS what the corpus already holds; it never runs a package manager or reaches the network.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from stayawake.bots.security.dependencies.ecosystems import canonical_ecosystem
from stayawake.utils import textsafe

MALICIOUS = "malicious"
VULNERABLE = "vulnerable"

_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{1,80}\Z")

_NAME_RE = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9][A-Za-z0-9._-]{0,99})?\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")


_REMOVE = {
    "npm": lambda n: f"npm uninstall {n}",
    "pypi": lambda n: f"pip uninstall -y {n}",
    "gem": lambda n: f"gem uninstall {n}",
    "cargo": lambda n: f"cargo remove {n}",
    "composer": lambda n: f"composer remove {n}",
    "nuget": lambda n: f"dotnet remove package {n}",
    "golang": lambda n: f"go mod edit -droprequire {n} && go mod tidy",
}


def _quoted(name: str, version: str = "0") -> tuple[str, str] | None:
    """Takes a package name and a version. Returns them shell-quoted, or None when either is not a
    plain package identifier."""
    if not _NAME_RE.match(name) or not _VERSION_RE.match(version):
        return None
    return shlex.quote(name), shlex.quote(version)


def removal_command(ecosystem: str, name: str) -> str | None:
    """The uninstall command for `ecosystem`. Returns None for an unknown ecosystem, or when the
    name is not a plain package identifier."""
    fn = _REMOVE.get(canonical_ecosystem(ecosystem))
    safe = _quoted(name)
    return fn(safe[0]) if fn and safe else None


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
    """What saw found about one flagged dependency: the sentence for the report, whether the
    package is known-malicious or carries an advisory, the package as `name@version`, and the
    command to remove it when saw can build one."""

    advice: str
    state: str
    package: str
    name: str
    command: str | None = None


@dataclass(frozen=True)
class DependencyAction:
    """One flagged package, and the command to remove it when saw can build one."""

    package: str
    command: str | None = None


@dataclass(frozen=True)
class DependencyActions:
    """The flagged packages of one scan, split by what saw found."""

    malicious: tuple[DependencyAction, ...] = ()
    vulnerable: tuple[DependencyAction, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.malicious or self.vulnerable)


def _coordinate(name: str, version: str) -> str:
    """Takes a package name and version. Returns `name@version`, safe to print."""
    shown = textsafe.plain(name, 100)
    return f"{shown}@{textsafe.plain(version, 40)}" if version else shown


def vulnerability_fix(ecosystem: str, name: str, version: str,
                      fixed_version: str | None) -> DependencyFix:
    """The fix for an ordinary CVE on a dependency. Takes the ecosystem, the package name, the
    version in this project and the first patched version, or None when the advisory publishes
    none. Returns a `DependencyFix` naming the affected version."""
    if fixed_version:
        return DependencyFix(
            f"{name} {version} is affected by this advisory. Move off it — read the advisory for "
            "the versions it covers.", VULNERABLE, _coordinate(name, version), name)
    return DependencyFix(
        f"No patched version is published for this advisory — remove or replace {name}, or pin it "
        "to a version outside the affected range.", VULNERABLE, _coordinate(name, version), name,
        removal_command(ecosystem, name))


def malware_fix(name: str, version: str = "", ecosystem: str = "") -> DependencyFix:
    """The fix for a known-malicious dependency. Takes the package name, its version and its
    ecosystem. Returns a `DependencyFix` that removes it."""
    return DependencyFix(
        f"Remove {name} now — it is a known-malicious package, so upgrading does not help. Purge it "
        "from your lockfile and installed tree, then rotate any credentials it could have read.",
        MALICIOUS, _coordinate(name, version), name, removal_command(ecosystem, name))


def external_advisory_fix(name: str, version: str, advisory_id: str, tool: str) -> DependencyFix:
    """The fix for an advisory an external auditor raised. Takes the package name, the advisory id
    and the auditor that reported it. Returns a `DependencyFix` that upgrades, naming the advisory
    to read rather than a version."""
    return DependencyFix(f"{name} {version} is reported by {tool} under {advisory_id}. Read the "
                         "advisory for the versions it covers.", VULNERABLE,
                         _coordinate(name, version), name)


def _field(item, name: str):
    """One field of a finding, whether it arrives as a `Finding` or as its payload dict."""
    return item.get(name) if isinstance(item, dict) else getattr(item, name, None)


def dependency_actions(*groups) -> DependencyActions:
    """What to hand an operator once per run. Takes any number of iterables of findings, as objects
    or as payload dicts. Returns a `DependencyActions`, empty when none of them names a package. A
    package flagged by several findings is carried once."""
    buckets: dict[str, dict[str, DependencyAction]] = {MALICIOUS: {}, VULNERABLE: {}}
    for group in groups:
        for item in group:
            package = _field(item, "package")
            bucket = buckets.get(_field(item, "dependency_state"))
            if package and bucket is not None:
                bucket.setdefault(package, DependencyAction(package, _field(item, "fix_command")))
    return DependencyActions(malicious=tuple(buckets[MALICIOUS].values()),
                             vulnerable=tuple(buckets[VULNERABLE].values()))


def _capped(actions: tuple[DependencyAction, ...], limit: int):
    """Takes the actions for one heading and the most a surface will show. Returns those to show
    and how many were left out."""
    return actions[:limit], max(0, len(actions) - limit)


def markdown_lines(actions: tuple[DependencyAction, ...], limit: int) -> list[str]:
    """Takes the actions under one heading and the most to show. Returns the lines: each package
    as a comment, then the commands that remove them."""
    shown, left_out = _capped(actions, limit)
    lines = [f"#   {a.package}" for a in shown]
    if left_out:
        lines.append(f"#   \u2026and {left_out} more")
    return lines + [textsafe.plain(a.command, 300) for a in shown if a.command]


def plain_lines(actions: tuple[DependencyAction, ...], limit: int) -> list[str]:
    """Takes the actions under one heading and the most to show. Returns the lines: each package
    as a comment, then the commands that remove them."""
    shown, left_out = _capped(actions, limit)
    lines = [f"  #   {a.package}" for a in shown]
    if left_out:
        lines.append(f"  #   \u2026and {left_out} more")
    return lines + [f"  {textsafe.plain(a.command, 300)}" for a in shown if a.command]
