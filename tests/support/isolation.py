#!/usr/bin/env python3
"""Run the test suite in a home of its own."""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

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


def _others_can_write(folder: Path) -> bool:
    """Tell whether another account can write to a folder or any folder above it. Takes the folder."""
    for each in (folder, *folder.parents):
        try:
            if each.stat().st_mode & 0o002:
                return True
        except OSError:
            continue
    return False


def homes_folder() -> Path:
    """Return the folder test homes are made in."""
    temporary = Path(tempfile.gettempdir()).resolve()
    if os.name != "posix" or not _others_can_write(temporary):
        return temporary
    homes = REAL_HOME / "saw-test-homes"
    homes.mkdir(mode=0o700, exist_ok=True)
    atexit.register(_remove_if_empty, homes)
    return homes


def _remove_if_empty(folder: Path) -> None:
    """Remove a folder when nothing is left in it. Takes the folder."""
    try:
        folder.rmdir()
    except OSError:
        pass


def new_home() -> Path:
    """Create a home whose git config holds only a test identity. Returns its path."""
    home = Path(tempfile.mkdtemp(prefix=PREFIX, dir=homes_folder())).resolve()
    (home / ".gitconfig").write_text(TEST_IDENTITY)
    return home


def _with_home(entry, home: Path):
    """Return `entry` from the account database with its home folder replaced by `home`."""
    fields = list(entry)
    fields[5] = str(home)
    return pwd.struct_passwd(fields)


def point_account_database_at(home: Path) -> None:
    """Make the account database name `home` as this account's home. Takes the home."""
    if pwd is None or not hasattr(os, "getuid"):
        return
    this_account = os.getuid()
    by_uid, by_name = pwd.getpwuid, pwd.getpwnam

    def getpwuid(uid):
        entry = by_uid(uid)
        return _with_home(entry, home) if entry.pw_uid == this_account else entry

    def getpwnam(name):
        entry = by_name(name)
        return _with_home(entry, home) if entry.pw_uid == this_account else entry

    pwd.getpwuid, pwd.getpwnam = getpwuid, getpwnam


def isolate(home: Path) -> None:
    """Point the environment and the account database at `home`. Takes the home."""
    kept = {name: os.environ[name] for name in KEPT_FROM_THE_CALLER if name in os.environ}
    os.environ.update({**environment_for(home), **kept})
    point_account_database_at(home)


def install() -> None:
    """Run this process in a test home: the one it inherited, else a new one removed at exit."""
    inherited = Path(os.environ.get("HOME", ""))
    if inherited.name.startswith(PREFIX) and inherited.is_dir():
        isolate(inherited)
        return
    home = new_home()
    atexit.register(shutil.rmtree, home, True)
    isolate(home)
