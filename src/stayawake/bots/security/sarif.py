#!/usr/bin/env python3
"""SARIF 2.1.0 emitter for the security scanner.

A pure output/observability layer over the payload `service.scan()` already builds:
it maps each finding to a SARIF `result` so findings surface in GitHub's code-scanning
UI (Security tab + inline PR annotations) once the report is uploaded with
`github/codeql-action/upload-sarif`. It detects nothing new and needs no GitHub
environment to write — outside CI it is simply another report file.

SARIF `level` is informational only; the build gate stays the process exit code
(`service.scan` → `--fail-on-findings`).
"""
from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path
from typing import Any

from stayawake.bots.security import redaction
from stayawake.utils import textsafe
from stayawake.utils.io import write_json

try:                                       # version is derived from the git tag at build time
    __version__ = _pkg_version("stayawakebot")
except PackageNotFoundError:               # running from a source tree without an installed dist
    __version__ = "0+unknown"

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "saw"
INFORMATION_URI = "https://github.com/Ndevu12/stayAwakeBot"

_LEVEL_BY_SEVERITY = {"critical": "error", "high": "error", "medium": "warning"}


def _level(severity: str) -> str:
    return _LEVEL_BY_SEVERITY.get(severity, "note")


def _name(signature_id: str) -> str:
    """A human-readable rule name derived from the signature id (PascalCase-ish),
    since GitHub surfaces `name` alongside the opaque `id` in triage."""
    return "".join(part.capitalize() for part in signature_id.replace("_", "-").split("-")) or signature_id


def _uri(result: dict, path: str) -> str:
    """artifactLocation URI. Local findings carry a workspace-relative path that maps
    straight onto changed lines for inline PR annotations; remote-clone findings have no
    PR diff, so we prefix the repo slug to give them a sensible non-workspace location
    (they render in the Security tab but not inline, by design)."""
    if result.get("source") == "remote":
        return f"{result['target']}/{path}"
    return path


def _fingerprint(signature_id: str, path: str, line: int | None) -> str:
    """Stable per-finding fingerprint (signature + location) so GitHub can carry a
    dismissal/triage decision across runs even as surrounding lines shift."""
    raw = f"{signature_id}|{path}|{line if line is not None else ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _rule(finding: dict) -> dict[str, Any]:
    """A reportingDescriptor (rule) for one signature, so triage shows real metadata
    instead of a bare id. `help`/`fullDescription` are built from category + description."""
    sig = finding["signature_id"]
    category = finding.get("category", "")
    description = finding.get("description", "")
    return {
        "id": sig,
        "name": _name(sig),
        "shortDescription": {"text": f"{category}: {sig}" if category else sig},
        "fullDescription": {"text": description or sig},
        "help": {"text": f"Category: {category}\n\n{description}".strip()},
        "defaultConfiguration": {"level": _level(finding.get("severity", ""))},
        "properties": {"category": category, "tags": [category] if category else []},
    }


def _message(finding: dict) -> str:
    text = finding.get("description") or finding["signature_id"]
    fp = redaction.redact(finding.get("evidence"))
    return f"{text}\n\nEvidence (redacted): {redaction.render_redacted(fp)}" if fp else text


def _result(result: dict, finding: dict, rule_index: int) -> dict[str, Any]:
    sig = finding["signature_id"]
    path = finding["path"]
    line = finding.get("line")
    artifact = {"uri": _uri(result, path)}
    physical: dict[str, Any] = {"artifactLocation": artifact}
    if line is not None:                       # omit region when the finding has no line
        physical["region"] = {"startLine": line}
    return {
        "ruleId": sig,
        "ruleIndex": rule_index,
        "level": _level(finding.get("severity", "")),
        "message": {"text": _message(finding)},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"sawSignatureLocation/v1": _fingerprint(sig, path, line)},
        "properties": {
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "category": finding.get("category"),
            "vector": finding.get("vector"),
            "remediation": finding.get("remediation"),
            "target": result.get("target"),
            "source": result.get("source"),
        },
    }


def build_sarif(payload: dict) -> dict[str, Any]:
    """Map a `service.scan()` payload to a SARIF 2.1.0 log (pure; no I/O).

    Rules are deduplicated to one reportingDescriptor per `signature_id` seen, in first-
    appearance order; every result references its rule by `ruleIndex`."""
    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for r in payload.get("results", []):
        for f in r.get("findings", []):
            sig = f["signature_id"]
            if sig not in rule_index:
                rule_index[sig] = len(rules)
                rules.append(_rule(f))
            results.append(_result(r, f, rule_index[sig]))
    errored = [r for r in payload.get("results", []) if r.get("error")]
    if errored:
        rules.append(NOT_SCANNED_RULE)
        results.extend(_not_scanned_result(r, len(rules) - 1) for r in errored)
    unscanned = [_unscanned(r) for r in errored]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "informationUri": INFORMATION_URI,
                "version": __version__,
                "rules": rules,
            }},
            "invocations": [{"executionSuccessful": not unscanned,
                             "toolExecutionNotifications": unscanned}],
            "results": results,
        }],
    }


NOT_SCANNED_ID = "saw-target-not-scanned"
NOT_SCANNED_RULE: dict[str, Any] = {
    "id": NOT_SCANNED_ID,
    "name": "TargetNotScanned",
    "shortDescription": {"text": "A target could not be scanned"},
    "fullDescription": {"text": "A target saw could not scan is not clean. Scan it again."},
    "help": {"text": "A target saw could not scan is not clean. Scan it again."},
    "defaultConfiguration": {"level": "error"},
    "properties": {"category": "scan", "tags": ["scan"]},
}


def _not_scanned_text(result: dict) -> str:
    """Say that a target could not be scanned. Takes one result of the payload. Returns the
    sentence, with the reason after it."""
    target = textsafe.plain(str(result.get("target") or ""), limit=200)
    reason = textsafe.plain(str(result.get("error") or ""), limit=200)
    return f"{target} could not be scanned and is not clean. Reason: {reason}"


def _not_scanned_result(result: dict, rule_index: int) -> dict[str, Any]:
    """Build the alert for a target the scan could not complete. Takes one result of the payload
    and the index of its rule. Returns a SARIF result at error level, located at the target."""
    target = str(result.get("target") or ".")
    return {
        "ruleId": NOT_SCANNED_ID,
        "ruleIndex": rule_index,
        "level": "error",
        "message": {"text": _not_scanned_text(result)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": target}}}],
        "partialFingerprints": {"sawSignatureLocation/v1": _fingerprint(NOT_SCANNED_ID, target,
                                                                          None)},
        "properties": {"target": result.get("target"), "source": result.get("source")},
    }


def _unscanned(result: dict) -> dict[str, Any]:
    """Build the notification for a target the scan could not complete. Takes one result of the
    payload. Returns a SARIF notification at error level."""
    return {"level": "error", "message": {"text": _not_scanned_text(result)}}


def write_sarif(payload: dict, path: str | Path) -> Path:
    """Write the SARIF log for `payload` to `path` (atomic, via write_json)."""
    out = Path(path)
    write_json(out, build_sarif(payload))
    return out
