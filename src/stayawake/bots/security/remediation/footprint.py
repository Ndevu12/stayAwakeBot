#!/usr/bin/env python3
"""Signature-driven excision of a confirmed footprint from a file's text."""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Callable

from stayawake.bots.security.matchers.base import globs_ok
from stayawake.bots.security.remediation.gates import (
    _carries_payload, _ext, _is_subsequence, _seam_strip, codeloader_content_sig)

CODE_LOADER = "code-loader"
GIT_MARKER = "git-marker"
REMOVE_FILE = "remove-file"
_IGNORE_FILE = ".gitignore"
_IGNORE_FILE_IGNORING_ITSELF = frozenset({".gitignore", "/.gitignore"})


def foreign_path(finding) -> str | None:
    """The path of a wholly-foreign file to remove whole, or None when the finding is not one."""
    if getattr(finding, "remediation", None) != REMOVE_FILE:
        return None
    return (getattr(finding, "path", "") or "") or None


def _marker_patterns(path: str, signatures) -> list[re.Pattern]:
    """The compiled git-marker patterns that apply to `path`."""
    out = []
    for s in signatures:
        if s.get("category") != GIT_MARKER or not s.get("pattern"):
            continue
        if globs_ok(path, s):
            out.append(re.compile(s["pattern"], re.IGNORECASE | re.MULTILINE))
    return out


def _matches_any(text: str, patterns: list[re.Pattern]) -> bool:
    return any(p.search(text) for p in patterns)


def lines_beside_markers(path: str) -> frozenset[str]:
    """Name the lines removed from `path` along with its markers.
    Takes the file's path. Returns those lines, or an empty set."""
    if PurePosixPath(path).name == _IGNORE_FILE:
        return _IGNORE_FILE_IGNORING_ITSELF
    return frozenset()


def line_marker_strip(text: str, patterns: list[re.Pattern],
                      beside: frozenset[str] = frozenset()) -> str | None:
    """Remove the marker lines, and the lines in `beside`, from `text`.
    Takes the text, the marker patterns and the lines that go with a marker. Returns the stripped
    text, or None when nothing can be stripped."""
    if not patterns:
        return None
    lines = text.splitlines(keepends=True)
    if not any(_matches_any(ln, patterns) for ln in lines):
        return None
    kept = [ln for ln in lines if not _matches_any(ln, patterns) and ln.strip() not in beside]
    result = "".join(kept)
    if _matches_any(result, patterns) or not _is_subsequence(result, text):
        return None
    return result


def carries_code_loader(signatures) -> Callable[[str], bool]:
    """`carries(text) -> bool` for a code-loader payload, from the content signatures alone."""
    content_sig = codeloader_content_sig(signatures)
    return lambda text: _carries_payload(text, content_sig)


def code_loader_corrector(path: str, signatures) -> Callable[[str], "str | None"]:
    """`corrector(text) -> clean_text | None` that excises a code-loader concealment seam from
    `path`, using its extension and the content signatures."""
    content_sig = codeloader_content_sig(signatures)
    ext = _ext(path)
    return lambda text: _seam_strip(text, ext, content_sig)


def carries_footprint(finding, signatures) -> Callable[[str], bool] | None:
    """`carries(text) -> bool` for this finding's footprint, or None when its category is not
    excised here."""
    category = getattr(finding, "category", None)
    path = getattr(finding, "path", "") or ""
    if category == CODE_LOADER:
        return carries_code_loader(signatures)
    if category == GIT_MARKER:
        patterns = _marker_patterns(path, signatures)
        if not patterns:
            return None
        return lambda text: bool(text) and _matches_any(text, patterns)
    return None


def corrector_for(finding, signatures) -> Callable[[str], "str | None"] | None:
    """Build the corrector that strips this finding's footprint from a file's text.
    Takes the finding and the signatures. Returns `corrector(text) -> clean_text | None`, or None
    when the finding has none."""
    category = getattr(finding, "category", None)
    path = getattr(finding, "path", "") or ""
    if category == CODE_LOADER:
        return code_loader_corrector(path, signatures)
    if category == GIT_MARKER:
        patterns = _marker_patterns(path, signatures)
        if not patterns:
            return None
        beside = lines_beside_markers(path)
        return lambda text: line_marker_strip(text, patterns, beside)
    return None
