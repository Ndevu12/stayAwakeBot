#!/usr/bin/env python3
"""Host filesystem drop-artifacts — staged ingress tooling + data bundled for exfil (T1105/T1074)."""
from __future__ import annotations

import getpass
import os
import socket
import tempfile
from pathlib import Path

from .models import HygieneIssue, _WIPER_NOTE

#
# Distinct from the runner / OS-service PERSISTENCE probes above (#1092/#1094): these are the
# drop-files this wave stages on a developer host — downloaded tooling and stolen data bundled
# before exfil. Some are weak on their own (a stray ~/.node_modules, an npm cache), so a LONE weak
# indicator is `info`; a strong, specific IoC or a corroborated set (>=2) is a `warning`. A positive
# means persistence may be LIVE, so the guidance follows the rotate-LAST order (#1088), never first.
# Every probe is a read-only stat/listdir and degrades to nothing when a path is absent/unreadable.

def _host_user_tag() -> str | None:
    """`<hostname>$<username>` — the name the wave gives a staged exfil archive on this host."""
    try:
        host = socket.gethostname().split(".")[0]
        user = getpass.getuser()
    except Exception:                       # gethostname/getuser can fail on odd hosts — degrade
        return None
    return f"{host}${user}" if host and user else None


def _first_child_named(directory: Path, prefix: str) -> Path | None:
    try:
        for entry in sorted(directory.iterdir()):
            if entry.name.startswith(prefix):
                return entry
    except OSError:
        pass
    return None


def _sideloaded_python_dir() -> Path | None:
    """A Windows `%LOCALAPPDATA%\\…\\Python3127\\` dir carrying the sideloaded interpreter/archiver
    (python.exe/python.zip/python.7z/7zr.exe). No-op off Windows (LOCALAPPDATA unset)."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return None
    sideload = {"python.exe", "python.zip", "python.7z", "7zr.exe"}
    for pattern in ("Python3127", "*/Python3127", "*/*/Python3127"):   # bounded, not a full walk
        try:
            for d in Path(local).glob(pattern):
                try:
                    if d.is_dir() and {f.name.lower() for f in d.iterdir()} & sideload:
                        return d
                except OSError:
                    continue
        except OSError:
            continue
    return None


def _staged_secret_scanner(dirs) -> Path | None:
    """A trufflehog secret-scanner BINARY staged in a cache/temp dir (T1588.002/T1552). Matches a
    FILE only — trufflehog's own `~/.cache/trufflehog` DIR (a legit user's cache) is not a hit."""
    for d in dirs:
        for name in ("trufflehog", "trufflehog.exe"):
            p = d / name
            try:
                if p.is_file():
                    return p
            except OSError:
                continue
    return None


def _host_artifacts() -> tuple[list[str], list[str]]:
    """Return (strong, weak) descriptions of detected host-IoC drop artifacts."""
    home = Path.home()
    tmp_dirs = sorted({Path("/tmp"), Path(tempfile.gettempdir())}, key=str)
    strong: list[str] = []
    weak: list[str] = []

    def _present(p: Path) -> bool:
        try:
            return p.exists()
        except OSError:
            return False

    # Weak drop-files — rarely benign, but each is a single low-confidence indicator.
    if _present(home / ".node_modules"):
        weak.append(f"{home}/.node_modules (payload-created)")
    for t in tmp_dirs:
        if _present(t / ".npm"):
            weak.append(f"{t}/.npm")
        if _present(t / "get-pip.py"):
            weak.append(f"{t}/get-pip.py")

    # Strong, specific IoCs.
    tag = _host_user_tag()                                  # <host>$<user> staged exfil archive
    if tag:
        for d in (home, home / ".npm", *tmp_dirs, Path.cwd()):
            match = _first_child_named(d, tag)
            if match is not None:
                strong.append(f"{match} (<host>$<user> exfil staging archive)")
                break
    sideloaded = _sideloaded_python_dir()
    if sideloaded is not None:
        strong.append(f"{sideloaded} (sideloaded Python3127 interpreter)")
    scanner = _staged_secret_scanner((home / ".cache", home / ".npm", *tmp_dirs))
    if scanner is not None:
        strong.append(f"{scanner} (staged secret-scanner binary)")
    return strong, weak


def check_host_artifacts() -> list[HygieneIssue]:
    """Detect host filesystem drop-files this wave stages on a developer workstation.

    FP-bounded: a strong/specific IoC or a corroborated set (>=2) is a `warning`; a lone weak
    indicator is `info`. SAFETY: a positive means persistence may be live, so the remediation
    follows the rotate-LAST order (#1088) — never advise rotating a credential first."""
    strong, weak = _host_artifacts()
    found = strong + weak
    if not found:
        return []
    if strong or len(found) >= 2:
        return [HygieneIssue(
            id="host-drop-artifacts",
            severity="warning",
            title="Host filesystem artifacts consistent with a supply-chain payload",
            detail="Found: " + "; ".join(found) + ". These are ingress-tooling / data-staging "
                   "drop-files (T1105/T1074) this wave leaves on a developer host.",
            remediation="Do NOT rotate credentials first — treat as possible LIVE compromise. "
                        "Isolate the host, neutralize any persistence, rebuild from a known-clean "
                        f"image, and rotate credentials LAST — {_WIPER_NOTE}.",
        )]
    return [HygieneIssue(          # a single weak indicator — inform, don't alarm; still rotate-LAST
        id="host-drop-artifact-weak",
        severity="info",
        title="Possible supply-chain drop-file on this host",
        detail="Found: " + "; ".join(found) + ". Rarely benign, but only one weak indicator — "
               "verify whether you created it.",
        remediation="If you did not create it, treat as possible compromise: isolate the host and "
                    f"neutralize any persistence BEFORE rotating any credential ({_WIPER_NOTE}).",
    )]


