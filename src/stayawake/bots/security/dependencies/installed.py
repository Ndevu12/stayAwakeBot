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

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class InstalledPackage:
    ecosystem: str
    name: str
    version: str | None       # installed version from the on-disk manifest; None if unreadable
    path: str                 # rel path of the package's manifest, for anchoring a finding


class InstalledTree:
    """Read one ecosystem's PROJECT-LOCAL installed tree. Yields NOTHING when the tree is absent (e.g. a
    remote clone with no install) — the lockfile audit stays the coverage there. Never follows symlinks
    (workspace/local links are benign, and following them risks loops / repo escape)."""
    ecosystem: str = ""
    _MAX_DEPTH = 8            # bound a pathological nested tree

    def read(self, target) -> Iterator[InstalledPackage]:
        raise NotImplementedError


def _read_manifest(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


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
            yield InstalledPackage(self.ecosystem, data["name"],
                                   version if isinstance(version, str) else None,
                                   str(Path(manifest).relative_to(repo_root)))
        nested = Path(pkg_dir) / "node_modules"            # nested (dedupe-miss) installs
        if nested.is_dir():
            yield from self._walk(nested, repo_root, depth + 1)


# Registered providers (Open/Closed — add an ecosystem's tree here). npm first; Python/Composer next.
INSTALLED_TREES = (NpmInstalledTree(),)
