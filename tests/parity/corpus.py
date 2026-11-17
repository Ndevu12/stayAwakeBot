#!/usr/bin/env python3
"""Build the corpus both sides scan, the same bytes and commits every time."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from tests.support import samples

_FIXED_TIME = "2026-01-01T00:00:00+0000"
_IDENTITY = {"GIT_AUTHOR_NAME": "corpus", "GIT_AUTHOR_EMAIL": "corpus@example.invalid",
             "GIT_COMMITTER_NAME": "corpus", "GIT_COMMITTER_EMAIL": "corpus@example.invalid",
             "GIT_AUTHOR_DATE": _FIXED_TIME, "GIT_COMMITTER_DATE": _FIXED_TIME}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                   cwd=repo, env={**os.environ, **_IDENTITY}, check=True, capture_output=True)


def _commit_all(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)


def build(dest: Path) -> list[Path]:
    """Write the corpus into `dest`, replacing what is there. Takes the folder. Returns the targets."""
    shutil.rmtree(dest, ignore_errors=True)
    projects = samples.write_fixtures(dest / "projects")
    clean_repo, infected_history = dest / "clean-repo", dest / "infected-history"
    shutil.copytree(projects / "clean", clean_repo)
    _git(clean_repo, "init", "-q", "-b", "main")
    _commit_all(clean_repo, "clean project")
    shutil.copytree(projects / "clean", infected_history)
    _git(infected_history, "init", "-q", "-b", "main")
    _commit_all(infected_history, "clean project")
    _git(infected_history, "switch", "-q", "-c", "elsewhere")
    shutil.copytree(projects / "infected", infected_history, dirs_exist_ok=True)
    _commit_all(infected_history, "infected project")
    _git(infected_history, "switch", "-q", "main")
    return [projects / "clean", projects / "infected", clean_repo, infected_history]
