#!/usr/bin/env python3
"""Evidence redaction for *persisted* scan artifacts.

The live terminal and `--json` stdout show evidence in full — they are ephemeral. But
anything written to a file (a SARIF report, the opt-in `-d` bundle) or otherwise kept
must NOT re-distribute the live payload it just detected: a stable fingerprint is enough
to triage and de-duplicate, and it keeps committed/uploaded artifacts from shipping
malware verbatim. One responsibility: turn an evidence snippet into a safe fingerprint.
"""
from __future__ import annotations

import copy
import hashlib
from typing import Any

PREVIEW_LEN = 48


def redact(evidence: Any) -> dict[str, Any] | None:
    """Fingerprint an evidence snippet: stable SHA-256 + a short preview + length.

    Returns None for empty/None so callers can simply omit the field."""
    if not evidence:
        return None
    text = evidence if isinstance(evidence, str) else str(evidence)
    return {
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "preview": text[:PREVIEW_LEN],
        "len": len(text),
    }


def render_redacted(r: dict[str, Any]) -> str:
    """One-line human form of a redact() dict, for SARIF messages / markdown."""
    return f"sha256:{r['sha256'][:12]}… preview={r['preview']!r} len={r['len']}"


def redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Deep copy of a scan payload with every evidence snippet replaced by redact().

    ADVISORIES too, not only findings. They were skipped, so a kept-on-disk report persisted their
    evidence verbatim — contradicting the sink's own contract that a saved report must not
    re-distribute what it detected."""
    out = copy.deepcopy(payload)
    for result in out.get("results", []):
        for item in [*result.get("findings", []), *result.get("advisories", [])]:
            if item.get("evidence") is not None:
                item["evidence"] = redact(item["evidence"])
    return out
