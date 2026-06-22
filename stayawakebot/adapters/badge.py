#!/usr/bin/env python3
"""README health-badge adapter (single responsibility: rewrite the badge block)."""
from __future__ import annotations

from pathlib import Path

_START = "<!-- STAYAWAKEBOT_BADGE -->"
_END = "<!-- STAYAWAKEBOT_BADGE_END -->"


def update_readme_badge(readme_path: str | Path, healthy: int, total: int) -> None:
    p = Path(readme_path)
    content = p.read_text(encoding="utf-8") if p.exists() else ""
    color = "brightgreen" if healthy == total else "red"
    block = (f"{_START}\n"
             f"![Health](https://img.shields.io/badge/health-{healthy}%2F{total}%20up-{color})\n"
             f"{_END}")
    if _START in content and _END in content:
        start, end = content.index(_START), content.index(_END) + len(_END)
        new = content[:start] + block + content[end:]
    elif _START in content:
        new = content.replace(_START, block)
    else:
        new = block + "\n" + content
    p.write_text(new, encoding="utf-8")
