#!/usr/bin/env python3
"""README badge adapter (single responsibility: rewrite a marker-delimited badge).

Generic `set_badge` is reused for both the health and the security badges (DRY);
feature-specific wrappers keep their exact label/format.
"""
from __future__ import annotations

from pathlib import Path


def set_badge(readme_path: str | Path, marker: str, alt: str,
              message: str, color: str) -> None:
    start, end = f"<!-- {marker} -->", f"<!-- {marker}_END -->"
    block = (f"{start}\n"
             f"![{alt}](https://img.shields.io/badge/{message}-{color})\n"
             f"{end}")
    p = Path(readme_path)
    content = p.read_text(encoding="utf-8") if p.exists() else ""
    if start in content and end in content:
        s, e = content.index(start), content.index(end) + len(end)
        new = content[:s] + block + content[e:]
    elif start in content:
        new = content.replace(start, block)
    else:
        new = block + "\n" + content
    p.write_text(new, encoding="utf-8")


def update_readme_badge(readme_path: str | Path, healthy: int, total: int) -> None:
    """Availability health badge (unchanged format/markers)."""
    color = "brightgreen" if healthy == total else "red"
    set_badge(readme_path, "STAYAWAKEBOT_BADGE", "Health",
              f"health-{healthy}%2F{total}%20up", color)


def update_security_badge(readme_path: str | Path, infected: int, findings: int) -> None:
    """Security badge: green when clean, red with finding count otherwise."""
    if infected == 0:
        message, color = "security-clean", "brightgreen"
    else:
        message, color = f"security-{findings}%20findings", "red"
    set_badge(readme_path, "STAYAWAKEBOT_SECURITY_BADGE", "Security", message, color)
