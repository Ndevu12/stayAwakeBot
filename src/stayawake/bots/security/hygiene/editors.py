#!/usr/bin/env python3
"""Which editors are on this machine, and where each keeps the settings this tool reads.

Editors are FOUND, not listed. A name list only decides what a finding calls an editor; coverage
comes from the layout on disk, so a fork this tool has never been told about is still examined.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils import appdirs

_SETTINGS = "settings.json"

_STATE_DIR = "globalStorage"

_PER_WORKSPACE_DIR = "workspaceStorage"

_STATE_FILES = ("state.vscdb", "storage.json")

_DISPLAY_NAMES = {
    "Code": "VS Code",
    "Code - Insiders": "VS Code Insiders",
    "Code - OSS": "Code - OSS",
    "VSCodium": "VSCodium",
    "Cursor": "Cursor",
    "Windsurf": "Windsurf",
    "Positron": "Positron",
    "Trae": "Trae",
}

_NOT_MODELLED = {
    "JetBrains": "JetBrains IDEs",
    "Zed": "Zed",
    "zed": "Zed",
}


@dataclass(frozen=True)
class Editor:
    """One editor of the VS Code family, and the settings file it reads on start-up."""

    name: str
    settings: Path


@dataclass(frozen=True)
class Found:
    """What the search reached, and what it could not."""

    editors: list[Editor]
    unreadable: list[Path]
    not_modelled: list[str]


def _within(inner: Path, outer: Path) -> bool:
    """Whether `inner` really is inside `outer` once every link on the way is followed."""
    try:
        return inner.resolve().is_relative_to(outer.resolve())
    except OSError:
        return False


def _cannot_tell(user_dir: Path) -> bool:
    """Whether the answer for `user_dir` is unknown rather than no."""
    try:
        if not user_dir.is_dir():
            return False
    except OSError:
        return True
    return not os.access(user_dir, os.R_OK | os.X_OK)


def _settings_of(candidate: Path) -> tuple[Path | None, bool]:
    """The settings file inside `candidate`, and whether the answer is unknown rather than no.

    Corroborated: this decides what gets graded and written to, and a bare `User/settings.json` is
    a shape any application may hold. The state the editor writes for itself has to be there too.
    """
    user_dir = candidate / "User"
    try:
        settings = user_dir / _SETTINGS
        if not settings.is_file():
            return None, _cannot_tell(user_dir)
        state, workspaces = user_dir / _STATE_DIR, user_dir / _PER_WORKSPACE_DIR
        if not state.is_dir() or not workspaces.is_dir():
            return None, _cannot_tell(user_dir)
        if not any((state / name).exists() for name in _STATE_FILES):
            return None, _cannot_tell(user_dir)
    except OSError:
        return None, True
    if not _within(settings, candidate):
        return None, True
    return settings, False


def _display_name(candidate: Path) -> str:
    """What an operator calls this editor. Its own directory name when there is no better one."""
    return _DISPLAY_NAMES.get(candidate.name, candidate.name)


def _profile_label(directory: Path) -> str:
    """The name this profile gives itself. The directory's own name when it does not say."""
    try:
        data = json.loads((directory / "profile.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return directory.name
    name = data.get("name") if isinstance(data, dict) else None
    return name.strip() if isinstance(name, str) and name.strip() else directory.name


def _profiles(candidate: Path, parent: str) -> list[Editor]:
    """The profiles under an editor already recognised. Takes the editor's directory and the name
    it is called. Returns one editor per profile that holds settings."""
    root = candidate / "User" / "profiles"
    found: list[Editor] = []
    try:
        children = sorted(path for path in root.iterdir() if path.is_dir())
    except (FileNotFoundError, OSError):
        return []
    for child in children:
        settings = child / "settings.json"
        try:
            if not settings.is_file() or not _within(settings, candidate):
                continue
        except OSError:
            continue
        found.append(Editor(f"{parent} ({_profile_label(child)})", settings))
    return found


def installed(bases=None) -> Found:
    """Every editor of this family on this machine, in a stable order.

    Takes the directories to search, defaulting to this platform's own. Returns what was found,
    what could not be read, and which other editors are present but not modelled here.
    """
    editors: dict[str, Editor] = {}
    unreadable: list[Path] = []
    not_modelled: set[str] = set()
    for base in (appdirs.user_data_dirs() + appdirs.sandboxed_data_dirs()
                 if bases is None else bases):
        try:
            candidates = sorted(base.iterdir())
        except FileNotFoundError:
            continue
        except OSError:
            unreadable.append(base)
            continue
        for candidate in candidates:
            settings, unknown = _settings_of(candidate)
            if unknown:
                unreadable.append(candidate)
                continue
            if settings is not None:
                name = _display_name(candidate)
                editors.setdefault(str(settings), Editor(name, settings))
                for profile in _profiles(candidate, name):
                    editors.setdefault(str(profile.settings), profile)
                continue
            # Asked only of something that is not one of these: a name decides what an editor is
            # CALLED, never whether it is examined.
            if candidate.name in _NOT_MODELLED:
                not_modelled.add(_NOT_MODELLED[candidate.name])
    return Found(sorted(editors.values(), key=lambda e: (e.name, str(e.settings))),
                 unreadable, sorted(not_modelled))
