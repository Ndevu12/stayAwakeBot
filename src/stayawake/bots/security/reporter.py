#!/usr/bin/env python3
"""Security reporting: write a compact status.json from the scan results.

The scanner already writes reports/security/latest.json (+ latest.md). This adds
a trimmed machine-readable status, mirroring the availability split.
"""
from __future__ import annotations

import os
from pathlib import Path

from stayawake.core.io import read_json, write_json, resolve_writable_dir


def generate(latest_path: str | Path = "reports/security/latest.json",
             reports_dir: str | Path | None = None) -> None:
    latest = read_json(latest_path)
    if latest is None:
        print("security latest.json not found; run the scanner first")
        return
    summary = latest.get("summary", {})
    status = {
        "generated_at": latest.get("generated_at"),
        "summary": summary,
        "infected": [
            {"target": r["target"], "source": r["source"],
             "findings": r["summary"]["total"], "max_severity": r["summary"]["max_severity"]}
            for r in latest.get("results", []) if r.get("infected")
        ],
    }
    rdir = resolve_writable_dir(
        reports_dir or os.environ.get("STAYAWAKE_REPORTS_DIR") or "reports/security",
        label="security reports")
    write_json(rdir / "status.json", status)
    print(f"Security status updated ({summary.get('infected', 0)} infected, "
          f"{summary.get('findings', 0)} findings).")
