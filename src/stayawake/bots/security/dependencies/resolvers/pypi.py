#!/usr/bin/env python3
"""PyPI resolver — requirements.txt / poetry.lock / Pipfile.lock / uv.lock → `Purl`s (#1122).

The second `Resolver` implementation. Building it against the npm-era interface is what proves
that interface is right — it fit PyPI without change (only the shared whole-file read moved up to
the base class), so the interface is now frozen for the #1123 ecosystem fan-out.

Prefers lockfiles (exact + transitive). `requirements.txt` is the manifest analogue: only exact
`==` pins are taken; ranges/compound specs/unpinned lines are deferred to the lock, mirroring the
npm `package.json` rule. Package names are normalized to PEP 503 form (lowercase, runs of `-_.`
collapsed to `-`) — the same normalization OSV/PyPI advisories use — so a `Flask_Foo` pin and a
`flask-foo` advisory match.
"""
from __future__ import annotations

import re
from typing import Iterator

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver
from stayawake.bots.security.dependencies.resolvers._lockfiles import toml_packages
from stayawake.bots.security.jsonc import load_jsonc

_TOML_LOCKS = ("poetry.lock", "uv.lock")     # both: TOML with a [[package]] array of {name, version}
_PIPFILE_LOCK = "Pipfile.lock"               # JSON: {default|develop: {name: {version: "==x"}}}

# PEP 503 name normalization: case-insensitive, runs of -_. → a single -.
_NAME_SEP = re.compile(r"[-_.]+")
# An exact `==` pin AFTER markers/comments/options are stripped: `name[extras]==version`, nothing
# else (a compound `name==1,<2` or a range `name>=1` must NOT match — those defer to the lock).
_EXACT_PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)(?:\[[^\]]*\])?==(?P<version>[A-Za-z0-9._!+-]+)$")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization (case-insensitive, runs of `-_.` → a single `-`) — the form OSV/PyPI
    advisories and this resolver both key on. Public so the Python installed-tree provider normalizes
    identically (a `Flask_Foo` on disk reconciles with a `flask-foo` lock/advisory) — one shared
    function, not a copied regex (extract-after-2nd-use)."""
    return _NAME_SEP.sub("-", name.strip()).lower()


def _is_requirements(base: str) -> bool:
    """`requirements.txt` and its common variants (`requirements-dev.txt`, `requirements.prod.txt`)."""
    return base.startswith("requirements") and base.endswith(".txt")


class PyPiResolver(Resolver):
    ecosystem = "pypi"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            if _is_requirements(base):
                deps = _requirements_deps(self._read_whole(target, rel))
            elif base in _TOML_LOCKS:
                deps = toml_packages(self._read_whole(target, rel))
            elif base == _PIPFILE_LOCK:
                deps = _pipfile_lock_deps(self._read_whole(target, rel))
            else:
                continue
            for name, version in deps:
                yield ResolvedDependency(Purl(self.ecosystem, normalize_pypi_name(name), version), rel)


# ── requirements.txt — exact `==` pins only (ranges defer to the lockfile) ──
def _requirements_deps(text) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in "#-":       # comment, or an option/include (-r/-c/-e/--hash)
            continue
        line = line.split(";", 1)[0].split("#", 1)[0]      # drop env marker + inline comment
        line = re.split(r"\s+--", line, maxsplit=1)[0]     # drop trailing options (e.g. --hash=…)
        line = re.sub(r"\s*==\s*", "==", line).strip()     # `name == 1` → `name==1`
        m = _EXACT_PIN.match(line)
        if m:
            out.append((m.group("name"), m.group("version")))
    return out


# poetry.lock / uv.lock are parsed by the shared `toml_packages` helper (see resolve() above).


# ── Pipfile.lock — JSON default/develop with a "==x.y.z" version string ──
def _pipfile_lock_deps(text) -> list[tuple[str, str]]:
    data = load_jsonc(text or "")
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    for section in ("default", "develop"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, meta in deps.items():
            if isinstance(name, str) and isinstance(meta, dict):
                spec = meta.get("version")
                if isinstance(spec, str):
                    version = spec.lstrip("=").strip()      # "==1.2.3" → "1.2.3"
                    if version:
                        out.append((name, version))
    return out
