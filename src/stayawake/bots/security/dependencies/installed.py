#!/usr/bin/env python3
"""What's actually INSTALLED on disk, per ecosystem — the counterpart to the lockfile resolvers (#1144).

The dependency audit (dependency_audit.py) reads the LOCKFILE — what SHOULD be there — and matches
names@versions against the corpus. But the worm's real move is a postinstall that drops a package into the
installed tree WITHOUT editing the lockfile → invisible to a lockfile-only audit. An `InstalledTree` reads
the on-disk tree so the matcher can reconcile it against the lock: identity-on-disk (an installed
name@version is known-malicious) and GHOST (on disk, absent from the lock).

Same Open/Closed seam as `Resolver` — share the INTERFACE, not the layout (node_modules trees ≠ Python
site-packages dist-info ≠ Composer vendor/), the epic's "not too DRY" boundary. Only ecosystems with a
PROJECT-LOCAL installed tree get a provider: npm (node_modules) now, Python (site-packages) + Composer
(vendor) next. Go / Rust / NuGet install to a GLOBAL cache, not a per-project tree, so the on-disk-vs-lock
model doesn't apply there — their lockfile audit (+ toolchain verification) is the coverage. Value-first:
no provider where there's no local tree to check. Offline, stdlib only, no new deps.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from stayawake.bots.security.dependencies.resolvers.pypi import normalize_pypi_name


# The keys npm runs AUTOMATICALLY on `npm install` (T1546) — one source, shared with NpmManifestMatcher.
NPM_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare")


@dataclass
class InstalledPackage:
    ecosystem: str
    name: str
    version: str | None       # installed version from the on-disk manifest; None if unreadable
    path: str                 # rel path of the package's manifest, for anchoring a finding
    hooks: dict[str, str] | None = None   # install-time lifecycle scripts (npm), for the hook scan
    entries: tuple[str, ...] = ()         # rel paths of the package's entry files (main/bin), for the sweep


@dataclass
class TamperedFile:
    ecosystem: str
    package: str              # name@version the file belongs to
    path: str                 # rel path of the file whose bytes changed — anchors the finding
    detail: str


class InstalledTree:
    """Read one ecosystem's PROJECT-LOCAL installed tree. Yields NOTHING when the tree is absent (e.g. a
    remote clone with no install) — the lockfile audit stays the coverage there. Never follows symlinks
    (workspace/local links are benign, and following them risks loops / repo escape)."""
    ecosystem: str = ""
    _MAX_DEPTH = 8            # bound a pathological nested tree
    # Whether an on-disk package ABSENT from the lock reliably means a GHOST. True only when the
    # ecosystem's lock lists the FULL (transitive) install set — npm's package-lock does, so an
    # off-lock package is genuinely anomalous. A provider sets this False when the common lock is
    # incomplete (PyPI's requirements.txt lists only DIRECT deps → every transitive install would
    # false-positive as a ghost); identity-on-disk still runs there, ghost is suppressed.
    ghost_reconcilable: bool = True

    def read(self, target) -> Iterator[InstalledPackage]:
        raise NotImplementedError

    def tampered(self, target) -> Iterator[TamperedFile]:
        """Installed files whose on-disk bytes no longer match the package's OWN per-file integrity
        manifest → modified AFTER install (a payload injected into a dependency). Default: none — an
        ecosystem without an on-disk per-file manifest (npm's lockfile `integrity` hashes the published
        TARBALL, not the extracted tree, so it can't verify the installed files offline)."""
        return
        yield


def _read_manifest(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


_MAX_ENTRIES = 16          # bound the bins a pathological manifest can list


def _npm_entry_files(data: dict, pkg_dir: str, repo_root: Path) -> tuple[str, ...]:
    """Rel paths of a package's ENTRY files — `main` (default `index.js`) + `bin` (a string or
    `{name: path}`). These run on `require`/exec, so a novel malicious package hides its loader here;
    node_modules is content-pruned, so the entry sweep is the only thing that reads them. Kept WITHIN
    the package dir (a `main: "../../x"` escaping it is dropped); `.js` is assumed when an entry has no
    extension. Bounded to `_MAX_ENTRIES`."""
    cands: list[str] = [data["main"] if isinstance(data.get("main"), str) else "index.js"]
    b = data.get("bin")
    if isinstance(b, str):
        cands.append(b)
    elif isinstance(b, dict):
        cands += [v for v in b.values() if isinstance(v, str)]
    pkg_abs = os.path.abspath(pkg_dir)
    out: list[str] = []
    for c in cands[:_MAX_ENTRIES]:
        fp = os.path.normpath(os.path.join(pkg_dir, c))
        if not os.path.splitext(fp)[1]:
            fp += ".js"
        try:
            if os.path.commonpath([os.path.abspath(fp), pkg_abs]) != pkg_abs:
                continue                       # entry escapes the package dir → ignore
            out.append(str(Path(fp).relative_to(repo_root)))
        except ValueError:
            continue                           # not under repo_root / undecidable → skip
    return tuple(dict.fromkeys(out))           # dedup, preserve order


class NpmInstalledTree(InstalledTree):
    ecosystem = "npm"

    def read(self, target) -> Iterator[InstalledPackage]:
        root = target.root / "node_modules"
        if not root.is_dir():
            return
        yield from self._walk(root, target.root, 0)

    def _walk(self, nm_dir: Path, repo_root: Path, depth: int) -> Iterator[InstalledPackage]:
        if depth > self._MAX_DEPTH:
            return
        try:
            entries = sorted(os.scandir(nm_dir), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            if e.name in (".bin", ".cache") or e.name.startswith("."):
                continue
            if not e.is_dir(follow_symlinks=False):       # skip symlinked (workspace-linked) packages
                continue
            if e.name.startswith("@"):                     # a scope dir holds the real package dirs
                try:
                    scoped = sorted(os.scandir(e.path), key=lambda x: x.name)
                except OSError:
                    continue
                for s in scoped:
                    if s.is_dir(follow_symlinks=False):
                        yield from self._pkg(s.path, repo_root, depth)
                continue
            yield from self._pkg(e.path, repo_root, depth)

    def _pkg(self, pkg_dir: str, repo_root: Path, depth: int) -> Iterator[InstalledPackage]:
        manifest = os.path.join(pkg_dir, "package.json")
        data = _read_manifest(manifest)
        if data and isinstance(data.get("name"), str):
            version = data.get("version")
            scripts = data.get("scripts")
            hooks = ({k: scripts[k] for k in NPM_LIFECYCLE_KEYS
                      if isinstance(scripts.get(k), str)} or None) if isinstance(scripts, dict) else None
            yield InstalledPackage(self.ecosystem, data["name"],
                                   version if isinstance(version, str) else None,
                                   str(Path(manifest).relative_to(repo_root)), hooks,
                                   _npm_entry_files(data, pkg_dir, repo_root))
        nested = Path(pkg_dir) / "node_modules"            # nested (dedupe-miss) installs
        if nested.is_dir():
            yield from self._walk(nested, repo_root, depth + 1)


class PythonInstalledTree(InstalledTree):
    """Python's project-local installed tree = a venv's `site-packages`, where each installed package is
    a `<name>-<version>.dist-info/` (wheel install) or `<name>.egg-info/` (legacy/editable) dir carrying
    a `METADATA`/`PKG-INFO` header block. The 2nd `InstalledTree` implementation — building it against the
    npm-era interface froze that interface (it fit without change). Names are PEP 503-normalized so a
    `Flask_Foo` on disk reconciles with a `flask-foo` lock/advisory, exactly as the resolver does.

    GHOST detection is deferred for Python (identity-on-disk still runs): the common lock,
    `requirements.txt`, lists only DIRECT deps, so every transitive package in site-packages would
    false-positive as off-lock. A follow-up can enable ghost reconciliation only when a COMPLETE lock
    (poetry.lock / uv.lock / Pipfile.lock) is present — until then it stays off to avoid the FP."""
    ecosystem = "pypi"
    ghost_reconcilable = False
    _MAX_HASH_BYTES = 4_000_000          # skip hashing a single huge (data) file — the tamper vector is
                                         # a payload in a SOURCE file, which is small; bounds per-file work
    _INTEGRITY_BUDGET = 500_000_000      # total bytes hashed per scan — a DoS backstop for a giant tree

    def _site_packages(self, target) -> Iterator[Path]:
        exclude = getattr(target.opts, "exclude_dirs", set())
        seen: set[str] = set()
        for sp in self._find_site_packages(target.root, exclude):
            try:
                key = str(sp.resolve())
            except OSError:
                continue
            if key not in seen:
                seen.add(key)
                yield sp

    def read(self, target) -> Iterator[InstalledPackage]:
        for sp in self._site_packages(target):
            yield from self._read_dist_infos(sp, target.root)

    def _find_site_packages(self, root: Path, exclude) -> Iterator[Path]:
        """Bounded walk for directories named `site-packages` (a venv can live anywhere / be named
        anything — `.venv`, `backend/env`, …). Prunes excluded/VCS/symlinked dirs, never descends INTO a
        found site-packages, and bounds depth — so a non-Python or huge repo can't make this expensive."""
        for dirpath, dirnames, _ in os.walk(root):     # followlinks=False (default)
            if len(Path(dirpath).relative_to(root).parts) >= self._MAX_DEPTH:
                dirnames[:] = []
                continue
            kept = []
            for d in dirnames:
                if d in exclude or d == ".git":
                    continue
                full = os.path.join(dirpath, d)
                if os.path.islink(full):               # don't follow symlinked dirs (escape / loop)
                    continue
                if d == "site-packages":
                    yield Path(full)                   # read it, but don't walk its package subtree
                    continue
                kept.append(d)
            dirnames[:] = kept

    def _read_dist_infos(self, sp_dir: Path, repo_root: Path) -> Iterator[InstalledPackage]:
        try:
            entries = sorted(os.scandir(sp_dir), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            if not e.is_dir(follow_symlinks=False):
                continue
            if e.name.endswith(".dist-info"):
                pkg = self._read_metadata(os.path.join(e.path, "METADATA"), repo_root)
            elif e.name.endswith(".egg-info"):
                pkg = self._read_metadata(os.path.join(e.path, "PKG-INFO"), repo_root)
            else:
                continue
            if pkg is not None:
                yield pkg

    def _read_metadata(self, meta_path: str, repo_root: Path) -> InstalledPackage | None:
        """Parse the `Name:`/`Version:` headers of a METADATA/PKG-INFO block (RFC822-style; headers end
        at the first blank line)."""
        name = version = None
        try:
            with open(meta_path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not line.strip():
                        break
                    low = line.lower()
                    if low.startswith("name:") and name is None:
                        name = line.split(":", 1)[1].strip()
                    elif low.startswith("version:") and version is None:
                        version = line.split(":", 1)[1].strip()
                    if name and version:
                        break
        except OSError:
            return None
        if not name:
            return None
        return InstalledPackage(self.ecosystem, normalize_pypi_name(name),
                                version or None, str(Path(meta_path).relative_to(repo_root)))

    def tampered(self, target) -> Iterator[TamperedFile]:
        """Verify each installed file against its package's `.dist-info/RECORD` sha256 — a Python-unique
        offline tamper check (a wheel's RECORD carries a per-file hash; npm has no on-disk equivalent).
        A mismatch means the file was modified AFTER install: a payload injected into a dependency. Only
        entries WITH a `sha256=` hash are checked, so `.pyc`/`__pycache__`/RECORD-self (no hash) are
        skipped → 0 false positives on a clean install (measured). Per-file and total hashing is bounded."""
        budget = self._INTEGRITY_BUDGET
        for sp in self._site_packages(target):
            try:
                entries = sorted(os.scandir(sp), key=lambda e: e.name)
            except OSError:
                continue
            for e in entries:
                if not (e.name.endswith(".dist-info") and e.is_dir(follow_symlinks=False)):
                    continue
                pkg = self._read_metadata(os.path.join(e.path, "METADATA"), target.root)
                label = f"{pkg.name}@{pkg.version}" if pkg else e.name[:-len(".dist-info")]
                sp_abs = os.path.abspath(sp)
                for rel, expected in _record_hashes(os.path.join(e.path, "RECORD")):
                    fp = os.path.normpath(os.path.join(sp, rel))   # matches sp's abs/rel form (for read + path)
                    # A RECORD path must stay INSIDE site-packages — a crafted `../../etc/passwd` or an
                    # absolute path must never be read. abspath BOTH sides for the check so commonpath can't
                    # ValueError on an absolute-vs-relative mix (a relative scan root + absolute RECORD entry).
                    try:
                        inside = os.path.commonpath([os.path.abspath(fp), sp_abs]) == sp_abs
                    except ValueError:
                        inside = False                    # different drives / undecidable → treat as escape
                    if not inside:
                        continue
                    try:
                        size = os.path.getsize(fp)
                    except OSError:
                        continue                          # listed-but-absent file → not a tamper signal
                    if os.path.islink(fp) or size > self._MAX_HASH_BYTES:
                        continue                          # skip symlinks + huge data files (bounded)
                    if size > budget:
                        return                            # total hashing budget spent (DoS backstop)
                    budget -= size
                    got = _sha256_record(fp)
                    if got is not None and got != expected:
                        yield TamperedFile(self.ecosystem, label,
                                           str(Path(fp).relative_to(target.root)),
                                           "on-disk bytes differ from the package's RECORD sha256")


def _record_hashes(record_path: str) -> Iterator[tuple[str, str]]:
    """`(relpath, "sha256=<b64>")` for each RECORD row that carries a sha256 (CSV — a path may be
    quoted). Rows with no hash (`.pyc`, RECORD itself) are skipped."""
    try:
        with open(record_path, encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) >= 2 and row[1].startswith("sha256="):
                    yield row[0], row[1]
    except OSError:
        return


def _sha256_record(path: str) -> str | None:
    """`sha256=<urlsafe-b64-no-pad>` of a file's bytes — the exact form RECORD stores."""
    try:
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).digest()
    except OSError:
        return None
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# Registered providers (Open/Closed — add an ecosystem's tree here). npm + Python now; Composer next.
INSTALLED_TREES = (NpmInstalledTree(), PythonInstalledTree())
