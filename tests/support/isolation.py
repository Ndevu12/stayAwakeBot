#!/usr/bin/env python3
"""Run the test suite in a home of its own."""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path
from unittest import mock

try:
    import pwd
except ImportError:
    pwd = None

PREFIX = "saw-test-home-"
REAL_HOME = Path.home().resolve()
KEPT_FROM_THE_CALLER = ("SAW_ADVISORY_CACHE_DIR",)
TEST_IDENTITY = "[user]\n\tname = saw test\n\temail = saw-test@example.invalid\n"


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
        "CARGO_HOME": os.environ.get("CARGO_HOME") or str(REAL_HOME / ".cargo"),
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME") or str(REAL_HOME / ".rustup"),
    }


def new_home() -> Path:
    """Create a home whose git config holds only a test identity. Returns its path."""
    home = Path(tempfile.mkdtemp(prefix=PREFIX)).resolve()
    (home / ".gitconfig").write_text(TEST_IDENTITY)
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


def isolate(home: Path) -> None:
    """Point the environment and the account database at `home`. Takes the home."""
    kept = {name: os.environ[name] for name in KEPT_FROM_THE_CALLER if name in os.environ}
    for patch in [mock.patch.dict(os.environ, {**environment_for(home), **kept}), *account_database_for(home)]:
        patch.start()


def install() -> None:
    """Run this process in a test home: the one it inherited, else a new one removed at exit."""
    inherited = Path(os.environ.get("HOME", ""))
    if inherited.name.startswith(PREFIX) and inherited.is_dir():
        isolate(inherited)
        return
    home = new_home()
    atexit.register(shutil.rmtree, home, True)
    isolate(home)
