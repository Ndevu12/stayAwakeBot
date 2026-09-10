#!/usr/bin/env python3
"""Signature-driven excision of a confirmed footprint from a file's text."""
from __future__ import annotations

import re
from typing import Callable

from stayawake.bots.security.matchers.base import globs_ok
from stayawake.bots.security.remediation.gates import (
    _carries_payload, _ext, _is_subsequence, _seam_strip, codeloader_content_sig)

CODE_LOADER = "code-loader"
GIT_MARKER = "git-marker"
QUARANTINE_FILE = "quarantine-file"


def foreign_path(finding) -> str | None:
    """The path of a wholly-foreign file to remove whole, or None when the finding is not one."""
    if getattr(finding, "remediation", None) != QUARANTINE_FILE:
        return None
    return (getattr(finding, "path", "") or "") or None


def _marker_patterns(path: str, signatures) -> list[re.Pattern]:
    """The compiled git-marker patterns that apply to `path`."""
    out = []
    for s in signatures:
        if s.get("category") != GIT_MARKER or not s.get("pattern"):
            continue
        if globs_ok(path, s):
            out.append(re.compile(s["pattern"], re.IGNORECASE))
    return out


def _matches_any(text: str, patterns: list[re.Pattern]) -> bool:
    return any(p.search(text) for p in patterns)


def line_marker_strip(text: str, patterns: list[re.Pattern]) -> str | None:
    """`text` with every line a pattern matches removed. None if nothing matched, a pattern still
    matches the result, or the result is not a subsequence of `text`."""
    if not patterns:
        return None
    lines = text.splitlines(keepends=True)
    kept = [ln for ln in lines if not _matches_any(ln, patterns)]
    if len(kept) == len(lines):
        return None
    result = "".join(kept)
    if _matches_any(result, patterns) or not _is_subsequence(result, text):
        return None
    return result


def carries_footprint(finding, signatures) -> Callable[[str], bool] | None:
    """`carries(text) -> bool` for this finding's footprint, or None when its category is not
    excised here."""
    category = getattr(finding, "category", None)
    path = getattr(finding, "path", "") or ""
    if category == CODE_LOADER:
        content_sig = codeloader_content_sig(signatures)
        return lambda text: _carries_payload(text, content_sig)
    if category == GIT_MARKER:
        patterns = _marker_patterns(path, signatures)
        if not patterns:
            return None
        return lambda text: bool(text) and _matches_any(text, patterns)
    return None


def corrector_for(finding, signatures) -> Callable[[str], "str | None"] | None:
    """`corrector(text) -> clean_text | None` for this finding, or None when its category is not
    excised here."""
    category = getattr(finding, "category", None)
    path = getattr(finding, "path", "") or ""
    if category == CODE_LOADER:
        content_sig = codeloader_content_sig(signatures)
        ext = _ext(path)
        return lambda text: _seam_strip(text, ext, content_sig)
    if category == GIT_MARKER:
        patterns = _marker_patterns(path, signatures)
        if not patterns:
            return None
        return lambda text: line_marker_strip(text, patterns)
    return None
