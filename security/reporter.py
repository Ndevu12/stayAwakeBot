#!/usr/bin/env python3
"""Security reporting: update the README security badge + a compact status.json.

The scanner already writes reports/security/latest.json (+ latest.md). This adds
the badge and a trimmed machine-readable status, mirroring the availability split.
"""
from __future__ import annotations

from pathlib import Path

from shared.adapters.badge import update_security_badge
from shared.io import read_json, write_json


def generate(latest_path: str | Path = "reports/security/latest.json",
             reports_dir: str | Path = "reports/security",
             readme: str | Path = "README.md") -> None:
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
    write_json(Path(reports_dir) / "status.json", status)
    update_security_badge(readme, summary.get("infected", 0), summary.get("findings", 0))
    print(f"Security badge + status updated ({summary.get('infected', 0)} infected, "
          f"{summary.get('findings', 0)} findings).")
