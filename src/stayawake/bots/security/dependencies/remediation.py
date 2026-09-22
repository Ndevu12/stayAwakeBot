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

REMOVE = "remove"
UPGRADE = "upgrade"

_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{1,80}\Z")

_NAME_RE = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9][A-Za-z0-9._-]{0,99})?\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")


def _npm(n: str, v: str) -> str: return f"npm install {n}@{v}"
def _pypi(n: str, v: str) -> str: return f"pip install '{n}>={v}'"
def _gem(n: str, v: str) -> str: return f"bundle update {n} --conservative"
def _cargo(n: str, v: str) -> str: return f"cargo update -p {n} --precise {v}"
def _composer(n: str, v: str) -> str: return f"composer require {n}:>={v}"
def _nuget(n: str, v: str) -> str: return f"dotnet add package {n} --version {v}"
def _golang(n: str, v: str) -> str: return f"go get {n}@{v if v.startswith('v') else 'v' + v}"


_UPGRADE = {"npm": _npm, "pypi": _pypi, "gem": _gem, "cargo": _cargo,
            "composer": _composer, "golang": _golang, "nuget": _nuget}

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


def upgrade_command(ecosystem: str, name: str, fixed_version: str) -> str | None:
    """The install-this-version command for `ecosystem`. Returns None for an unknown ecosystem, or
    when the name or version is not a plain package identifier."""
    fn = _UPGRADE.get(canonical_ecosystem(ecosystem))
    safe = _quoted(name, fixed_version)
    return fn(*safe) if fn and safe else None


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
    """What to do about one flagged dependency: the sentence for the report, the command to run,
    and which action it is. `command` is a `#` comment line when saw can build no command."""

    advice: str
    action: str
    command: str


@dataclass(frozen=True)
class DependencyAction:
    """One command for the operator to run."""

    command: str


@dataclass(frozen=True)
class DependencyActions:
    """The advice for one scan, split by action."""

    remove: tuple[DependencyAction, ...] = ()
    upgrade: tuple[DependencyAction, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.remove or self.upgrade)


def _by_hand(name: str, what: str) -> str:
    """Takes a package name and what to do about it. Returns a `#` comment line."""
    return f"# {textsafe.plain(name, 100)} — {what}"


def vulnerability_fix(ecosystem: str, name: str, fixed_version: str | None) -> DependencyFix:
    """The fix for an ordinary CVE on a dependency. Takes the ecosystem, the package name and the
    first patched version, or None when the advisory publishes no fix. Returns a `DependencyFix`:
    an upgrade with the ecosystem's command, or a removal."""
    if fixed_version:
        base = f"Upgrade {name} to {fixed_version} or later (first patched version)."
        cmd = upgrade_command(ecosystem, name, fixed_version)
        return DependencyFix(f"{base}  {cmd}" if cmd else f"{base}  Bump it in your manifest and "
                             "reinstall.", UPGRADE,
                             cmd or _by_hand(name, f"upgrade to {textsafe.plain(fixed_version, 40)}"))
    return DependencyFix(
        f"No patched version is published for this advisory — remove or replace {name}, or pin it "
        "to a version outside the affected range.", REMOVE,
        removal_command(ecosystem, name) or _by_hand(name, "remove, replace or pin it"))


def malware_fix(name: str, ecosystem: str = "") -> DependencyFix:
    """The fix for a known-malicious dependency. Takes the package name and its ecosystem. Returns
    a `DependencyFix` that removes it."""
    return DependencyFix(
        f"Remove {name} now — it is a known-malicious package, so upgrading does not help. Purge it "
        "from your lockfile and installed tree, then rotate any credentials it could have read.",
        REMOVE,
        removal_command(ecosystem, name) or _by_hand(name, "remove it and replace it"))


def external_advisory_fix(name: str, advisory_id: str, tool: str) -> DependencyFix:
    """The fix for an advisory an external auditor raised. Takes the package name, the advisory id
    and the auditor that reported it. Returns a `DependencyFix` that upgrades, naming the advisory
    to read rather than a version."""
    return DependencyFix(f"Upgrade {name} to a release that resolves {advisory_id} (see the "
                         f"advisory), then re-run {tool}.", UPGRADE,
                         _by_hand(name, f"upgrade to a release fixing "
                                        f"{textsafe.plain(advisory_id, 40)}"))


def _field(item, name: str):
    """One field of a finding, whether it arrives as a `Finding` or as its payload dict."""
    return item.get(name) if isinstance(item, dict) else getattr(item, name, None)


def dependency_actions(*groups) -> DependencyActions:
    """The commands to hand an operator once per run. Takes any number of iterables of findings, as
    objects or as payload dicts. Returns a `DependencyActions`, empty when none of them carries a
    command. The same command raised by several findings is carried once."""
    buckets: dict[str, dict[str, DependencyAction]] = {REMOVE: {}, UPGRADE: {}}
    for group in groups:
        for item in group:
            command = _field(item, "fix_command")
            bucket = buckets.get(_field(item, "dependency_action"))
            if command and bucket is not None:
                bucket.setdefault(command, DependencyAction(command))
    return DependencyActions(remove=tuple(buckets[REMOVE].values()),
                             upgrade=tuple(buckets[UPGRADE].values()))


def _capped(actions: tuple[DependencyAction, ...], limit: int):
    """Takes the actions for one heading and the most a surface will show. Returns those to show
    and how many were left out."""
    return actions[:limit], max(0, len(actions) - limit)


def markdown_lines(actions: tuple[DependencyAction, ...], limit: int) -> list[str]:
    """Takes the actions under one heading and the most to show. Returns the command lines."""
    shown, left_out = _capped(actions, limit)
    lines = [textsafe.plain(a.command, 300) for a in shown]
    return lines + ([f"# \u2026and {left_out} more"] if left_out else [])


def plain_lines(actions: tuple[DependencyAction, ...], limit: int) -> list[str]:
    """Takes the actions under one heading and the most to show. Returns the command lines."""
    shown, left_out = _capped(actions, limit)
    lines = [f"  {textsafe.plain(a.command, 300)}" for a in shown]
    return lines + ([f"  # \u2026and {left_out} more"] if left_out else [])
