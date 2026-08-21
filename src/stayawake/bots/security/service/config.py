#!/usr/bin/env python3
"""Scan-configuration resolution: turn the YAML config + CLI flags into a `ScanOptions`,
and gate the run on the advisory DB when asked. Pure decisions — no scanning, no output I/O.
"""
from __future__ import annotations

import sys
from pathlib import Path

from stayawake.utils.config import load_yaml
from stayawake.bots.security.targets import ScanOptions
from stayawake.bots.security.config import resolve_config


def _read_config(config_path: str | None) -> dict | None:
    return resolve_config(config_path)


_BUILD_OUTPUT_DIRS = {"dist", "build", "out", ".next"}


def _as_bool(value, default: bool) -> bool:
    """Coerce a config value to bool WITHOUT the string footgun — `bool("false")` is True, so a
    quoted YAML `external_audit: "false"` (or `"no"`/`"off"`/`"0"`) would otherwise read as True and
    silently ENABLE a security-sensitive option (external audit leaves the offline sandbox). A value
    that isn't a recognizable boolean falls back to `default`."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes", "on"):
            return True
        if s in ("false", "0", "no", "off", ""):
            return False
    return default


def _options(settings: dict, *, no_advisories: bool = False,
             external_audit: bool = False, deep: bool = False) -> ScanOptions:
    base = ScanOptions()
    exclude = set(settings.get("exclude_dirs", base.exclude_dirs))
    scan_build_outputs = _as_bool(settings.get("scan_build_outputs"), base.scan_build_outputs)
    if scan_build_outputs:
        exclude -= _BUILD_OUTPUT_DIRS          # let build outputs be traversed (matcher gates the rest)
    return ScanOptions(
        exclude_dirs=exclude,
        max_file_bytes=int(settings.get("max_file_bytes", base.max_file_bytes)),
        remote_clone_depth=int(settings.get("remote_clone_depth", base.remote_clone_depth)),
        scan_build_outputs=scan_build_outputs,
        # `--deep` (or config `deep: true`): content-scan installed dependency CODE with the confirmed
        deep=deep or _as_bool(settings.get("deep"), base.deep),
        # The offline CVE-advisory tier is ON by default; `--no-advisories` or config
        # `dependency_advisories: false` turns the section off.
        dependency_advisories=(not no_advisories) and _as_bool(
            settings.get("dependency_advisories"), base.dependency_advisories),
        # External auditors are the one opt-in that leaves the offline sandbox (subprocess + a tool's
        # own network) — CLI flag OR config, off by default. Strict bool coercion so a quoted
        # `"false"` can't silently enable it.
        external_audit=external_audit or _as_bool(
            settings.get("external_audit"), base.external_audit),
    )


def jobs_setting(settings: dict) -> int | None:
    """Config `settings.jobs` as a worker count, or None for AUTO. Accepts an int, a numeric
    string, or "auto"/"" (→ None). A junk value falls back to AUTO rather than crashing the scan;
    a value below 1 is clamped to 1 (force sequential). CLI `-j/--jobs` takes precedence over this."""
    value = settings.get("jobs")
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in ("auto", ""):
        return None
    try:
        count = int(value)
    except (TypeError, ValueError):
        return None
    return max(count, 1)


def _require_db_or_error() -> int | None:
    """`--require-db` gate: a non-zero exit (with a stderr reason) if the advisory DB is absent or
    fails its content-hash integrity check; None if it's present and valid."""
    from stayawake.bots.security.dependencies import db
    st = db.cache_status()
    if not st.get("present"):
        print("saw scan --require-db: advisory DB not found — run `saw db update`.", file=sys.stderr)
        return 2
    if not st.get("schema_compatible", True):
        # Unusable (older format → scan falls back to the inline seed), but not tampering. Fail
        print(f"saw scan --require-db: advisory DB is an older format (schema {st.get('schema')}) "
              "— run `saw db update`.", file=sys.stderr)
        return 2
    if not st.get("integrity_ok"):
        print("saw scan --require-db: advisory DB integrity check FAILED "
              f"({', '.join(st.get('mismatches', []))}) — run `saw db update`.", file=sys.stderr)
        return 2
    return None
