#!/usr/bin/env python3
"""Version comparators + OSV range evaluation (#1124).

An advisory range says "affected from `introduced` until `fixed`/`last_affected`"; deciding whether
a resolved version falls inside requires ordering versions the way that *ecosystem* orders them —
npm semver ≠ PEP 440 ≠ Gem::Version ≠ Maven's qualifier ordering. So each ecosystem has its own
comparator behind one interface (`is_version_in_range`); there is deliberately NO universal
`Version` class (the epic's not-too-DRY boundary).

Every comparator is **self-contained** (no third-party dependency — the tool stays offline and
minimal-dep): a comparator turns a version string into a Python-comparable key, or None when it
can't parse it (→ the range conservatively does NOT match, so an undecidable bound never raises a
false INFECTED). Shipped: semver (npm/Cargo/Go/Composer/NuGet + all `SEMVER`-typed ranges), PEP 440
(PyPI), Gem::Version (RubyGems), and a best-effort Maven ordering.
"""
from __future__ import annotations

import functools
import re
from typing import Callable

from stayawake.bots.security.dependencies.ecosystems import canonical_ecosystem
from stayawake.bots.security.dependencies.osv import OsvRange


# ── semver (npm, Cargo, Go, Composer, NuGet; and all SEMVER-typed ranges) ────────────────
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
    v = v.split("+", 1)[0]
    rel, _, pre = v.partition("-")
    parts = rel.split(".")
    try:
        release = tuple(int(p) for p in parts)
    except ValueError:
        return None
    release = release + (0,) * max(0, 4 - len(release))
    if not pre:
        prerelease: tuple = (1,)
    else:
        ids = []
        for ident in pre.split("."):
            if ident.isdigit():
                ids.append((0, int(ident), ""))
            else:
                ids.append((1, 0, ident))
        prerelease = (0, tuple(ids))
    return (release, prerelease)


# ── PEP 440 (PyPI) — mirrors packaging's canonical _cmpkey, vendored (no dependency) ─────
_PEP440_RE = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?:post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?
    \s*$
""", re.VERBOSE | re.IGNORECASE)
_PEP440_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1,
                    "c": 2, "rc": 2, "pre": 2, "preview": 2}


def pep440_key(version: str) -> tuple | None:
    """A comparable PEP 440 key, or None. Ordering: epoch, then release (trailing zeros trimmed),
    then the dev < pre < final < post structure (a dev-only release sorts below all pre-releases; a
    version with no dev sorts above one with)."""
    if not isinstance(version, str):
        return None
    m = _PEP440_RE.match(version.strip().lower())
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    rel = [int(x) for x in m.group("release").split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    release = tuple(rel)

    pre = (_PEP440_PRE_RANK[m.group("pre_l")], int(m.group("pre_n") or 0)) if m.group("pre_l") else None
    post = int(m.group("post_n1") or m.group("post_n2") or 0) if m.group("post") is not None else None
    dev = int(m.group("dev_n") or 0) if m.group("dev") is not None else None

    if pre is None and post is None and dev is not None:
        pre_key = (-1, 0, 0)                 # dev-only → before all pre-releases
    elif pre is None:
        pre_key = (1, 0, 0)                  # no pre → after pre (final/post)
    else:
        pre_key = (0,) + pre
    post_key = (-1, 0) if post is None else (0, post)
    dev_key = (0, dev) if dev is not None else (1, 0)    # has-dev sorts below no-dev
    return (epoch, release, pre_key, post_key, dev_key)


# ── Gem::Version (RubyGems) ──────────────────────────────────────────────────────────────
def _gem_segments(version: str) -> list | None:
    if not isinstance(version, str):
        return None
    toks = re.findall(r"\d+|[a-zA-Z]+", version.strip())
    if not toks:
        return None
    return [int(t) if t.isdigit() else t.lower() for t in toks]


def _gem_cmp(a: list, b: list) -> int:
    """RubyGems ordering: segments compared left to right, a missing segment is numeric 0, and a
    string (letter) segment is a pre-release that sorts BELOW any number."""
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        if x == y:
            continue
        xs, ys = isinstance(x, str), isinstance(y, str)
        if xs and ys:
            return -1 if x < y else 1
        if xs:                       # string < numeric (prerelease below release)
            return -1
        if ys:
            return 1
        return -1 if x < y else 1
    return 0


def gem_key(version: str):
    segs = _gem_segments(version)
    return None if segs is None else functools.cmp_to_key(_gem_cmp)(segs)


# ── Maven (best-effort subset of ComparableVersion) ──────────────────────────────────────
# Known qualifier ordering; aliases fold in. `""`/ga/final/release are the "null" level; qualifiers
# below it (alpha…snapshot) are pre-releases, `sp` is above it. Unknown qualifiers sort after known
# ones. A numeric item outranks any qualifier at the same position; numeric 0 equals the null level.
_MAVEN_QUALIFIERS = {"alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3,
                     "rc": -2, "cr": -2, "snapshot": -1,
                     "": 0, "ga": 0, "final": 0, "release": 0, "sp": 1}


def _maven_item_key(item) -> tuple:
    if isinstance(item, int):
        return (1, item, "")                         # numbers outrank qualifiers
    q = _MAVEN_QUALIFIERS.get(item)
    if q is not None:
        return (0, q, "")
    return (0, 100, item)                            # unknown qualifier: after known, lexical


def _maven_vs_null(item) -> int:
    """Compare a present item against the implicit "null" of a shorter version (−1/0/1). Numeric 0
    and the release qualifiers are null; alpha…snapshot are below it, `sp`/unknown above."""
    if isinstance(item, int):
        return (item > 0) - (item < 0)
    q = _MAVEN_QUALIFIERS.get(item)
    q = q if q is not None else 100
    return (q > 0) - (q < 0)


def _maven_cmp(a: list, b: list) -> int:
    for i in range(max(len(a), len(b))):
        if i >= len(a):
            c = -_maven_vs_null(b[i])
        elif i >= len(b):
            c = _maven_vs_null(a[i])
        else:
            ka, kb = _maven_item_key(a[i]), _maven_item_key(b[i])
            c = -1 if ka < kb else (1 if ka > kb else 0)
        if c:
            return c
    return 0


def maven_key(version: str):
    """A best-effort Maven ordering key. Handles numeric segments and the standard qualifiers
    (alpha/beta/milestone/rc/snapshot/ga/sp); exotic qualifier combinations are approximate — this
    tier is informational (no Maven malware uses bounded ranges), so an odd ordering never gates."""
    if not isinstance(version, str):
        return None
    items = [int(t) if t.isdigit() else t
             for part in re.split(r"[.\-]", version.strip().lower())
             for t in re.findall(r"\d+|[a-z]+", part)]
    return None if not items else functools.cmp_to_key(_maven_cmp)(items)


# ── range evaluation ─────────────────────────────────────────────────────────────────────
# PURL type → the key function for its `ECOSYSTEM`-typed ranges.
_ECOSYSTEM_KEY: dict[str, Callable[[str], object | None]] = {
    "npm": semver_key, "cargo": semver_key, "golang": semver_key,
    "composer": semver_key, "nuget": semver_key,
    "pypi": pep440_key, "gem": gem_key, "maven": maven_key,
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
