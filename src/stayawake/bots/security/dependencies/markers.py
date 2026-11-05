#!/usr/bin/env python3
"""Which package ecosystems a scanned project declares but leaves without a dependency audit."""
from __future__ import annotations

from fnmatch import fnmatch

# A manifest inside one of these is a dependency's own, not the scanned project's.
_VENDORED = frozenset({
    "vendor", "third_party", "third-party", "Pods", "bower_components", ".pub-cache",
    "node_modules", "packages", "example", "examples", "testdata", "fixtures",
})


def _first_party(rel: str) -> bool:
    return not any(part in _VENDORED for part in rel.split("/")[:-1])


def unaudited_ecosystems(files, resolved, resolvers) -> dict[str, str]:
    """{ecosystem: label} for each resolver whose manifest a first-party file matches while it
    resolved no dependency."""
    want = {r.ecosystem: (r.label, r.manifests) for r in resolvers
            if r.label and r.manifests and r.ecosystem not in resolved}
    found: dict[str, str] = {}
    for rel in files:
        if not want:
            break
        if not _first_party(rel):
            continue
        base = rel.rsplit("/", 1)[-1]
        for eco in list(want):
            label, manifests = want[eco]
            if any(fnmatch(base, m) for m in manifests):
                found[eco] = label
                del want[eco]
    return found
