"""The real repositories the corpus adds when a list of them is given, each at a fixed commit.

The list is TOML, one `[[repository]]` per entry with `name`, `url` and `commit`. It is read from
the file `SAW_PARITY_REPOSITORIES` names; without it the corpus stays offline.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

LIST_VARIABLE = "SAW_PARITY_REPOSITORIES"


@dataclass(frozen=True)
class Pinned:
    """One repository, and the commit the corpus holds it at."""
    name: str
    url: str
    commit: str


def list_path() -> Path | None:
    """Return the list file `SAW_PARITY_REPOSITORIES` names, or None when it names none."""
    named = os.environ.get(LIST_VARIABLE, "").strip()
    return Path(named) if named else None


def listed(path: Path) -> list[Pinned]:
    """Read the list. Takes its path. Returns each repository, in the order listed."""
    with path.open("rb") as handle:
        entries = tomllib.load(handle).get("repository", [])
    return [Pinned(entry["name"], entry["url"], entry["commit"]) for entry in entries]


def fingerprint(path: Path | None) -> bytes:
    """Return what the list contributes to the corpus fingerprint: its bytes, or nothing."""
    return hashlib.sha256(path.read_bytes()).digest() if path else b""


def _git(where: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=where, capture_output=True, text=True, check=True)
    return done.stdout.strip()


def fetched(pins: list[Pinned], into: Path) -> list[Path]:
    """Return a checkout of each repository at its commit, fetching the ones `into` lacks. Takes
    the repositories and the folder they are kept in. Raises ValueError when a checkout is not at
    its commit."""
    checkouts = []
    for pin in pins:
        where = into / f"{pin.name}-{pin.commit[:12]}"
        if not (where / ".git").is_dir():
            where.mkdir(parents=True, exist_ok=True)
            _git(where, "init", "-q")
            _git(where, "fetch", "-q", "--depth", "1", pin.url, pin.commit)
            _git(where, "checkout", "-q", "--detach", "FETCH_HEAD")
        if _git(where, "rev-parse", "HEAD") != pin.commit:
            raise ValueError(f"{pin.name} is not at {pin.commit}")
        checkouts.append(where)
    return checkouts
