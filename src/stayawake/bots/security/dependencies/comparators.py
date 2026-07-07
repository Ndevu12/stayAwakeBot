#!/usr/bin/env python3
"""Version comparators + OSV range evaluation (#1124).

An advisory range says "affected from `introduced` until `fixed`/`last_affected`"; deciding whether
a resolved version falls inside requires ordering versions the way that *ecosystem* orders them —
npm semver ≠ PEP 440 ≠ Gem::Version ≠ Maven's qualifier ordering. So each ecosystem has its own
comparator behind one interface (`is_version_in_range`); there is deliberately NO universal
`Version` class (the epic's not-too-DRY boundary).

Shipped here: a self-contained **semver** comparator, used for `SEMVER`-typed ranges and for the
`ECOSYSTEM` ranges of the semver-based ecosystems (npm, Cargo, Go, Composer, NuGet). PyPI (PEP 440),
RubyGems and Maven use non-semver ordering and are **deferred** — their ranges are not evaluated
yet (a range with no comparator, or an unparseable bound, conservatively does NOT match, so we
never raise a false INFECTED). Explicit-version matching still covers every ecosystem.
"""
from __future__ import annotations

import re
from typing import Callable

from stayawake.bots.security.dependencies.ecosystems import canonical_ecosystem
from stayawake.bots.security.dependencies.osv import OsvRange

# A version key is any object supporting `<`/`>=`; None means "could not parse" (→ no match).
VersionKey = object


def semver_key(version: str) -> tuple | None:
    """A comparable key for a semver version, or None if it isn't numeric-release semver.

    `(release, prerelease)`: release is the dotted numeric core padded to 4 fields (so a 3-part
    semver and a 4-part NuGet version compare cleanly, and `1.2` == `1.2.0`); a version WITHOUT a
    prerelease outranks one WITH (semver §11), and prerelease identifiers compare numerically then
    lexically (numeric < alphanumeric). Build metadata (`+…`) is ignored.
    """
    if not isinstance(version, str):
        return None
    v = version.strip()
    if v[:1] in ("v", "V"):
        v = v[1:]
    v = v.split("+", 1)[0]                       # drop build metadata
    rel, _, pre = v.partition("-")               # prerelease is after the first '-'
    parts = rel.split(".")
    try:
        release = tuple(int(p) for p in parts)
    except ValueError:
        return None                              # non-numeric release → not semver-comparable
    release = release + (0,) * max(0, 4 - len(release))
    if not pre:
        prerelease: tuple = (1,)                 # release sorts ABOVE any prerelease
    else:
        ids = []
        for ident in pre.split("."):
            if ident.isdigit():
                ids.append((0, int(ident), ""))          # numeric identifier
            else:
                ids.append((1, 0, ident))                # alphanumeric (sorts above numeric)
        prerelease = (0, tuple(ids))             # prerelease sorts BELOW release
    return (release, prerelease)


# PURL type → the key function for its `ECOSYSTEM`-typed ranges. Absent ⇒ ranges deferred.
_ECOSYSTEM_KEY: dict[str, Callable[[str], object | None]] = {
    "npm": semver_key, "cargo": semver_key, "golang": semver_key,
    "composer": semver_key, "nuget": semver_key,
    # "pypi": PEP 440, "gem": Gem::Version, "maven": Maven ordering — deferred (#1124 follow-up).
}


def _key_fn(range_type: str, ecosystem: str):
    if range_type == "SEMVER":
        return semver_key
    if range_type == "ECOSYSTEM":
        return _ECOSYSTEM_KEY.get(canonical_ecosystem(ecosystem))
    return None                                  # GIT (or unknown) → not evaluable here


def is_version_in_range(version: str, osv_range: OsvRange, ecosystem: str) -> bool:
    """True if `version` is inside `osv_range` for `ecosystem`. Conservative: an unknown range type,
    an ecosystem without a comparator, or an unparseable version/bound → False (never a false hit).

    Implements the OSV linear-scan: walk the events in version order maintaining an `affected` flag —
    `introduced` opens the window, `fixed`/`last_affected` close it (`introduced: "0"` = −∞)."""
    key = _key_fn(osv_range.type, ecosystem)
    if key is None:
        return False
    v = key(version)
    if v is None:
        return False

    events: list[tuple[str, object | None]] = []
    for kind, value in osv_range.events:
        if kind == "introduced" and value == "0":
            events.append((kind, None))          # −∞ sentinel
        else:
            pv = key(value)
            if pv is None:
                return False                     # an unparseable bound → can't decide → no match
            events.append((kind, pv))
    events.sort(key=lambda e: (0,) if e[1] is None else (1, e[1]))

    affected = False
    for kind, pv in events:
        if kind == "introduced":
            if pv is None or v >= pv:
                affected = True
        elif kind == "fixed":
            if v >= pv:
                affected = False
        elif kind == "last_affected":
            if v > pv:
                affected = False
    return affected


def version_in_any_range(version: str, ranges, ecosystem: str) -> bool:
    return any(is_version_in_range(version, r, ecosystem) for r in ranges)
