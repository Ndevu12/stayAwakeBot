#!/usr/bin/env python3
"""npm-ecosystem resolver — package.json + npm/yarn/pnpm lockfiles → `Purl`s (#1119).

Relocated verbatim (behaviour-preserving) from the pre-refactor `dependency_audit` matcher.
yarn and pnpm packages are npm-registry packages, so all three lockfile formats resolve to
the one `pkg:npm/…` ecosystem — hence a single resolver.

The campaign's PRIMARY spread is republishing backdoored versions of packages, so the next
`npm install` is the next victim — the payload lands in `node_modules` (which `saw` excludes)
and never touches the repo tree. This resolver reads what a repo DECLARES and LOCKS so the
matcher can flag a known-bad `name@version` before that install happens.

Supported: npm `package-lock.json` / `npm-shrinkwrap.json` (v1 `dependencies` tree +
v2/v3 `packages`), `yarn.lock` (classic v1 `version "x"` AND berry v2+ `version: x`), and
`pnpm-lock.yaml` (v5 `/name/version`, v6+/v9 `/name@version`, with `(peer)` or `_peer`
suffixes). Manifest ranges (`^4.2.11`) are deliberately NOT resolved — they're ambiguous, so
the lockfile's resolved version is the source of truth (only exact pins are emitted).
"""
from __future__ import annotations

import re
from typing import Iterator

import yaml

from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.dependencies.resolvers.base import Resolver
from stayawake.bots.security.jsonc import load_jsonc

_MANIFEST = "package.json"
_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")
_EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_DECLARED_DEP_FIELDS = ("dependencies", "devDependencies",
                        "optionalDependencies", "peerDependencies")
# Lockfiles must be parsed WHOLE (a head/tail-truncated lockfile is invalid JSON/YAML and
# yields nothing), so read up to this generous cap instead of the scan's default source cap.
# 32 MB covers any realistic lockfile while bounding memory on a pathological one.
_MAX_LOCKFILE_BYTES = 32_000_000
_MAX_NPM_V1_DEPTH = 100          # guard the recursive v1 `dependencies` walk against a crafted tree
# A pnpm `packages:` key: an optional leading '/', a name, then '@version' (v6+/v9) or '/version'
# (v5), then the version stops before a peer suffix ('(...)' or '_...'). The name capture is
# non-greedy so the version separator lands on the FIRST '@'/'/' that precedes a digit.
_PNPM_KEY = re.compile(r"^/?(?P<name>.+?)[@/](?P<version>\d+\.\d+\.\d+[0-9A-Za-z.\-+]*)")


class NpmResolver(Resolver):
    ecosystem = "npm"

    def resolve(self, target) -> Iterator[ResolvedDependency]:
        for rel in target.iter_files():
            base = rel.rsplit("/", 1)[-1]
            if base == _MANIFEST:
                deps = self._manifest_deps(self._read(target, rel))
            elif base in _NPM_LOCKS:
                deps = self._npm_lock_deps(self._read(target, rel))
            elif base == "yarn.lock":
                deps = self._yarn_lock_deps(self._read(target, rel))
            elif base == "pnpm-lock.yaml":
                deps = self._pnpm_lock_deps(self._read(target, rel))
            else:
                continue
            for name, version in deps:
                yield ResolvedDependency(Purl(self.ecosystem, name, version), rel)

    @staticmethod
    def _read(target, rel) -> str | None:
        """Read a manifest/lockfile WHOLE (bypassing the scan's head/tail truncation, which
        would turn a large lockfile into unparseable JSON/YAML). Falls back to read_text."""
        raw = target.read_bytes(rel, limit=_MAX_LOCKFILE_BYTES)
        if raw is not None:
            return raw.decode("utf-8", errors="replace")
        return target.read_text(rel)

    # ── package.json — exact-pinned declared deps only (ranges defer to the lockfile) ──
    def _manifest_deps(self, text) -> list[tuple[str, str]]:
        data = load_jsonc(text or "")
        if not isinstance(data, dict):
            return []
        out = []
        for field in _DECLARED_DEP_FIELDS:
            deps = data.get(field)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if isinstance(name, str) and isinstance(spec, str):
                    version = _exact_version(spec)
                    if version:
                        out.append((name, version))
        return out

    # ── npm — package-lock.json / npm-shrinkwrap.json (v2/v3 `packages` + v1 `dependencies`) ──
    def _npm_lock_deps(self, text) -> list[tuple[str, str]]:
        data = load_jsonc(text or "")
        if not isinstance(data, dict):
            return []
        out: list[tuple[str, str]] = []
        packages = data.get("packages")            # lockfile v2/v3: keyed by install path
        if isinstance(packages, dict):
            for path, meta in packages.items():
                if not (isinstance(path, str) and isinstance(meta, dict)):
                    continue
                version = meta.get("version")
                if "node_modules/" not in path or not isinstance(version, str):
                    continue
                # Prefer the authoritative `name` (set for aliased installs, where the install-path
                # segment is the ALIAS, not the real package); fall back to the path segment.
                name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
                if isinstance(name, str) and name:
                    out.append((name, version))
        self._walk_npm_v1(data.get("dependencies"), out, 0)   # lockfile v1: nested tree
        return out

    def _walk_npm_v1(self, deps, out, depth) -> None:
        if not isinstance(deps, dict) or depth > _MAX_NPM_V1_DEPTH:
            return
        for name, meta in deps.items():
            if not (isinstance(name, str) and isinstance(meta, dict)):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                out.append((name, version))
            self._walk_npm_v1(meta.get("dependencies"), out, depth + 1)

    # ── yarn.lock — classic (`version "x"`) and berry (`version: x`) ──
    def _yarn_lock_deps(self, text) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        names: list[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                header = line.rstrip()[:-1]                  # drop trailing ':'
                names = [_yarn_spec_name(part.strip().strip('"'))
                         for part in header.split(",")]
            elif stripped.startswith("version"):
                # classic: `version "4.2.11"`  |  berry: `version: 4.2.11`
                m = re.match(r'version:?\s+"?([^"\s]+)"?', stripped)
                if m:
                    for name in names:
                        if name:
                            out.append((name, m.group(1)))
        return out

    # ── pnpm-lock.yaml (`packages:` keyed by /name@version(peers) or /name/version_peer) ──
    def _pnpm_lock_deps(self, text) -> list[tuple[str, str]]:
        try:
            data = yaml.safe_load(text or "")
        except yaml.YAMLError:
            return []
        if not isinstance(data, dict):
            return []
        out: list[tuple[str, str]] = []
        for section in ("packages", "snapshots"):        # v9 splits packages/snapshots
            block = data.get(section)
            if isinstance(block, dict):
                for key in block:
                    nv = _pnpm_key_name_version(key)
                    if nv:
                        out.append(nv)
        return out


def _exact_version(spec: str) -> str | None:
    """An exactly-pinned semver (no range operator) → the version, else None. `^`/`~`/`>`/`<`/`*`/
    `x`/`||`/url/git/`npm:`alias specs are ranges/indirections and are left to the lockfile."""
    s = spec.strip().lstrip("=").strip()
    if s[:1] == "v" and s[1:2].isdigit():          # a `v1.2.3` pin → drop the leading v
        s = s[1:]
    return s if _EXACT_VERSION.match(s) else None


def _yarn_spec_name(spec: str) -> str:
    """`name` from a yarn `name@range` / `@scope/name@range` header spec — everything before the
    LAST '@' (a lone leading scope '@' is kept). Handles berry's `name@npm:^1.2.3` too."""
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


def _pnpm_key_name_version(key) -> tuple[str, str] | None:
    """(name, version) from a pnpm `packages:`/`snapshots:` key across v5 (`/name/version[_peer]`)
    and v6+/v9 (`/name@version[(peer)]`, leading '/' optional), scoped or not. The version is the
    semver at the first '@'/'/' boundary that precedes a digit; peer suffixes are excluded."""
    if not isinstance(key, str):
        return None
    m = _PNPM_KEY.match(key)
    if not m:
        return None
    return (m.group("name"), m.group("version"))
