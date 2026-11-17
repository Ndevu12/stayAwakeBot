#!/usr/bin/env python3
"""Run every test in a home of its own."""
from __future__ import annotations

import atexit
import functools
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import pwd
except ImportError:
    pwd = None

PREFIX = "saw-test-home-"
REAL_HOME = Path.home().resolve()
KEPT_FROM_THE_CALLER = ("SAW_ADVISORY_CACHE_DIR",)


def environment_for(home: Path) -> dict[str, str]:
    """Return the environment that points every per-user location at `home`. Takes the home."""
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"),
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_NAME": "saw test",
        "GIT_AUTHOR_EMAIL": "saw-test@example.invalid",
        "GIT_COMMITTER_NAME": "saw test",
        "GIT_COMMITTER_EMAIL": "saw-test@example.invalid",
    }


def new_home() -> Path:
    """Create an empty home with an empty git config. Returns its path."""
    home = Path(tempfile.mkdtemp(prefix=PREFIX)).resolve()
    (home / ".gitconfig").touch()
    return home


def _with_home(entry, home: Path):
    """Return `entry` from the account database with its home folder replaced by `home`."""
    fields = list(entry)
    fields[5] = str(home)
    return pwd.struct_passwd(fields)


def account_database_for(home: Path) -> list:
    """Return patches that make the account database name `home` as this account's home. Takes the
    home."""
    if pwd is None or not hasattr(os, "getuid"):
        return []
    this_account = os.getuid()
    by_uid, by_name = pwd.getpwuid, pwd.getpwnam

    def getpwuid(uid):
        entry = by_uid(uid)
        return _with_home(entry, home) if entry.pw_uid == this_account else entry

    def getpwnam(name):
        entry = by_name(name)
        return _with_home(entry, home) if entry.pw_uid == this_account else entry

    return [mock.patch.object(pwd, "getpwuid", getpwuid), mock.patch.object(pwd, "getpwnam", getpwnam)]


def isolate(home: Path) -> list:
    """Point the environment and the account database at `home`. Takes the home. Returns the
    started patches, for `release`."""
    kept = {name: os.environ[name] for name in KEPT_FROM_THE_CALLER if name in os.environ}
    patches = [mock.patch.dict(os.environ, {**environment_for(home), **kept}), *account_database_for(home)]
    for patch in patches:
        patch.start()
    return patches


def release(patches: list) -> None:
    """Stop the patches `isolate` started, last first."""
    for patch in reversed(patches):
        patch.stop()


def install() -> None:
    """Give the whole test run a home of its own, and every test a fresh one inside it."""
    session_home = new_home()
    atexit.register(shutil.rmtree, session_home, True)
    isolate(session_home)
    run = unittest.TestCase.run

    @functools.wraps(run)
    def run_in_its_own_home(self, result=None):
        home = new_home()
        patches = isolate(home)
        try:
            return run(self, result)
        finally:
            release(patches)
            shutil.rmtree(home, ignore_errors=True)

    unittest.TestCase.run = run_in_its_own_home
