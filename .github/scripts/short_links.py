#!/usr/bin/env python3
"""The docs site's short links: one redirect page at `go/<name>/` for each entry in
`docs/short-links.yml`, opening that page of the latest documentation.

    short_links.py write MAP SITE_ROOT    write the redirect pages under SITE_ROOT/go/
    short_links.py check MAP BUILT_SITE   confirm every target page and section exists in a build

A target is a path on this site, so a short link can only ever open saw's own documentation.
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path

import yaml

VERSION = "latest"
_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_TARGET = re.compile(r"[a-z0-9][a-z0-9/-]*/(?:#[a-z0-9][a-z0-9-]*)?")


def load(map_path: Path) -> dict[str, str]:
    """Read the short links. Takes the map's path. Returns each name with its target; raises
    ValueError when the map is empty, or a name or target is not a plain path on this site."""
    entries = yaml.safe_load(Path(map_path).read_text(encoding="utf-8"))
    if not isinstance(entries, dict) or not entries:
        raise ValueError(f"{map_path} holds no short links")
    for name, target in entries.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError(f"short link name {name!r} is not lowercase words joined by hyphens")
        if not isinstance(target, str) or not _TARGET.fullmatch(target) or "//" in target:
            raise ValueError(f"short link {name!r} targets {target!r}, which is not a page on this site")
    return entries


def redirect_page(target: str) -> str:
    """Build the page that sends a reader to one target. Takes the target. Returns the HTML."""
    where = html.escape(f"/{VERSION}/{target}", quote=True)
    return ("<!doctype html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '<meta charset="utf-8">\n'
            '<meta name="robots" content="noindex">\n'
            f'<meta http-equiv="refresh" content="0; url={where}">\n'
            f'<link rel="canonical" href="{where}">\n'
            "<title>saw documentation</title>\n"
            "</head>\n"
            f'<body><p><a href="{where}">Open the saw documentation</a></p></body>\n'
            "</html>\n")


def write(entries: dict[str, str], site_root: Path) -> list[Path]:
    """Write one redirect page per short link. Takes the links and the site's root folder. Returns
    the pages written."""
    written = []
    for name, target in sorted(entries.items()):
        page = Path(site_root) / "go" / name / "index.html"
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text(redirect_page(target), encoding="utf-8")
        written.append(page)
    return written


def missing(entries: dict[str, str], built_site: Path) -> list[str]:
    """Find short links whose page or section a built version of the site lacks. Takes the links
    and the folder that version was built into. Returns one line per link that would lead nowhere."""
    problems = []
    for name, target in sorted(entries.items()):
        path, _, section = target.partition("#")
        page = Path(built_site) / path / "index.html"
        if not page.is_file():
            problems.append(f"go/{name}: no page at {path}")
        elif section and f'id="{section}"' not in page.read_text(encoding="utf-8"):
            problems.append(f"go/{name}: {path} has no section #{section}")
    return problems


def main(argv: list[str]) -> int:
    """Run `write` or `check`. Takes the command line. Returns the process status."""
    if len(argv) != 4 or argv[1] not in ("write", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    entries = load(Path(argv[2]))
    if argv[1] == "write":
        for page in write(entries, Path(argv[3])):
            print(f"wrote {page}")
        return 0
    problems = missing(entries, Path(argv[3]))
    for problem in problems:
        print(f"::error::{problem}")
    if not problems:
        print(f"{len(entries)} short links lead to a page")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
