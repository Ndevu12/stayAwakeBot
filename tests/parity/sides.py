#!/usr/bin/env python3
"""Name the two saws the harness compares, and run them."""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Side:
    """One saw to run: its name, its command, and the environment it adds."""
    name: str
    command: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict)

    def run(self, args: list[str]) -> str:
        """Run this saw with `args`. Takes the arguments. Returns what it printed on stdout."""
        done = subprocess.run([*self.command, *args], env={**os.environ, **self.env},
                              capture_output=True, text=True, check=False)
        return done.stdout


def python_saw(name: str, source: Path) -> Side:
    """Return the Python saw whose package is in `source`. Takes a name and the `src` folder."""
    return Side(name, (sys.executable, "-m", "stayawake"), {"PYTHONPATH": str(source)})


def this_checkout() -> Side:
    """Return the saw in this checkout."""
    return python_saw("this checkout", REPO_ROOT / "src")


def main_at(commit: str, cache: Path) -> Side:
    """Return main's saw at `commit`, unpacked once into `cache`. Takes the commit and the cache."""
    source = cache / f"main-{commit}"
    if not (source / "src" / "stayawake").is_dir():
        archive = subprocess.run(["git", "archive", "--format=tar", commit, "src"], cwd=REPO_ROOT,
                                 capture_output=True, check=True).stdout
        source.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(source, filter="data")
    return python_saw(f"main at {commit[:12]}", source / "src")
