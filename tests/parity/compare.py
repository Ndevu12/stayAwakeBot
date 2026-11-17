#!/usr/bin/env python3
"""Compare what two saws printed for the same scan."""
from __future__ import annotations

import json
from collections import Counter

_VARIES_BY_RUN = ("generated_at",)


def normalized(printed: str) -> str:
    """Return a scan document with the fields that change on every run removed. Takes what saw
    printed. Returns the document as canonical JSON, or the text itself when it is not JSON."""
    try:
        document = json.loads(printed)
    except json.JSONDecodeError:
        return printed
    if isinstance(document, dict):
        for name in _VARIES_BY_RUN:
            document.pop(name, None)
    return json.dumps(document, sort_keys=False, indent=1)


def _findings_by_matcher(document: dict) -> dict[str, Counter]:
    by_target: dict[str, Counter] = {}
    for result in document.get("results", []):
        counted = Counter(json.dumps(f, sort_keys=True) for f in result.get("findings", []))
        by_target[result.get("target", "?")] = Counter(
            {json.loads(f).get("signature_id", "?"): n for f, n in counted.items()})
    return by_target


def differences(expected: str, actual: str) -> list[str]:
    """Return each difference between two printed scans. Takes both. Returns none when they match."""
    left, right = normalized(expected), normalized(actual)
    if left == right:
        return []
    found = ["the documents differ"]
    try:
        a, b = json.loads(left), json.loads(right)
    except json.JSONDecodeError:
        return found
    if not isinstance(a, dict) or not isinstance(b, dict):
        return found
    for name in sorted(set(a) | set(b)):
        if name != "results" and a.get(name) != b.get(name):
            found.append(f"{name}: {a.get(name)!r} != {b.get(name)!r}")
    ours, theirs = _findings_by_matcher(a), _findings_by_matcher(b)
    for target in sorted(set(ours) | set(theirs)):
        mine, other = ours.get(target, Counter()), theirs.get(target, Counter())
        for matcher in sorted(set(mine) | set(other)):
            if mine[matcher] != other[matcher]:
                found.append(f"{target}: {matcher} {mine[matcher]} != {other[matcher]}")
    return found
