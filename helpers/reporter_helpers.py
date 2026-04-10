#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(description="Generate reports from latest.json")
    p.add_argument("--latest", default="reports/latest.json", help="Path to latest.json")
    return p.parse_args()


def utc_iso_now():
    return datetime.now(timezone.utc).astimezone().isoformat()


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


def update_readme_badge(readme_path: Path, healthy: int, total: int):
    content = readme_path.read_text() if readme_path.exists() else ""
    badge_text = f"{healthy}%2F{total}%20up"
    color = "brightgreen" if healthy == total else "red"
    badge_block = (
        "<!-- STAYAWAKEBOT_BADGE -->\n"
        f"![Health](https://img.shields.io/badge/health-{badge_text}-{color})\n"
        "<!-- STAYAWAKEBOT_BADGE_END -->\n"
    )
    if "<!-- STAYAWAKEBOT_BADGE -->" in content:
        start = content.index("<!-- STAYAWAKEBOT_BADGE -->")
        end_marker = "<!-- STAYAWAKEBOT_BADGE_END -->"
        if end_marker in content:
            end = content.index(end_marker) + len(end_marker)
            new = content[:start] + badge_block + content[end:]
        else:
            new = content.replace("<!-- STAYAWAKEBOT_BADGE -->", badge_block)
    else:
        new = badge_block + "\n" + content
    readme_path.write_text(new)


def compute_uptime(url_name: str, history: list, cutoff: datetime) -> float:
    seen = [h for h in history if datetime.fromisoformat(h["generated_at"]) >= cutoff]
    if not seen:
        return 100.0
    checks = 0
    healthy = 0
    for run in seen:
        for u in run.get("urls", []):
            if u.get("name") == url_name:
                checks += 1
                if u.get("healthy"):
                    healthy += 1
    return round((healthy / checks) * 100.0, 1) if checks else 100.0
