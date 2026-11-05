#!/usr/bin/env python3
"""Manifest files that show a package ecosystem is present even without a lockfile."""
from __future__ import annotations

from fnmatch import fnmatch

# ecosystem (PURL type) -> (human label, manifest basenames or globs that prove it is present).
_MARKERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "npm":      ("npm", ("package.json",)),
    "pypi":     ("Python", ("pyproject.toml", "setup.py", "setup.cfg")),
    "cargo":    ("Rust", ("Cargo.toml",)),
    "golang":   ("Go", ("go.mod",)),
    "maven":    ("Java/Kotlin", ("pom.xml", "build.gradle", "build.gradle.kts")),
    "composer": ("PHP", ("composer.json",)),
    "gem":      ("Ruby", ("Gemfile",)),
    "nuget":    (".NET", ("*.csproj", "*.vbproj", "*.fsproj", "*.sln")),
    "pub":      ("Dart/Flutter", ("pubspec.yaml",)),
}


def detected_ecosystems(files) -> dict[str, str]:
    """{ecosystem: label} for each ecosystem whose manifest marker appears among `files`."""
    found: dict[str, str] = {}
    for rel in files:
        if len(found) == len(_MARKERS):
            break
        base = rel.rsplit("/", 1)[-1]
        for eco, (label, markers) in _MARKERS.items():
            if eco not in found and any(fnmatch(base, m) for m in markers):
                found[eco] = label
    return found
