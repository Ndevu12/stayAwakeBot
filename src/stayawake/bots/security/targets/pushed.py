#!/usr/bin/env python3
"""The file versions a push would publish, presented through the interface a directory uses."""
from __future__ import annotations

from stayawake.lib.git.objects import read_blobs

from .history import HistoryTarget

_READ_AHEAD_BYTES = 64 << 20


class PushedTarget(HistoryTarget):
    """One stored version of each path a push introduces, and the merge commits it pushes."""

    source = "push"

    def __init__(self, root, display: str, opts, versions: dict[str, str],
                 links: dict[str, list[str]] | None = None, merges: list[str] | None = None):
        super().__init__(root, display, opts, {path: [oid] for path, oid in versions.items()}, 0,
                         links)
        self.merge_scope = list(merges or ())
        self.read_ahead, sizes = read_blobs(root, list(versions.values()),
                                            max_each=opts.max_file_bytes, max_total=_READ_AHEAD_BYTES)
        self.sizes = sizes
