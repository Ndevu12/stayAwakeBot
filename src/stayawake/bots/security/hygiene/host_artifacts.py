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


def _host_artifacts() -> tuple[list[str], list[tuple[str, Path]]]:
    """Return (strong, weak) detected host-IoC drop artifacts. `strong` are descriptions; `weak` are
    (description, path) pairs so a caller can optionally content-scan the path to corroborate (#1221)."""
    home = Path.home()
    tmp_dirs = sorted({Path("/tmp"), Path(tempfile.gettempdir())}, key=str)
    strong: list[str] = []
    weak: list[tuple[str, Path]] = []

    def _present(p: Path) -> bool:
        try:
            return p.exists()
        except OSError:
            return False

    # Weak drop-files — a single low-confidence indicator each. Described NEUTRALLY (not "payload"):
    # each has a mundane explanation (a manual `npm install` in $HOME, a pip bootstrap) as well as the
    # worm one, and existence alone can't tell them apart — so we surface, we don't accuse. The path
    # rides along so `--verify` can content-scan it (see check_host_artifacts).
    if _present(home / ".node_modules"):
        weak.append((f"{home}/.node_modules (an npm tree in your home dir — unusual location)",
                     home / ".node_modules"))
    for t in tmp_dirs:
        if _present(t / ".npm"):
            weak.append((f"{t}/.npm", t / ".npm"))
        if _present(t / "get-pip.py"):
            weak.append((f"{t}/get-pip.py", t / "get-pip.py"))

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


def check_host_artifacts(verify: bool = False) -> list[HygieneIssue]:
    """Detect host filesystem drop-files this wave stages on a developer workstation.

    FP-bounded: a strong/specific IoC or a corroborated set (>=2) is a `warning`; a lone weak
    indicator is `info`. SAFETY: a positive means persistence may be live, so the remediation
    follows the rotate-LAST order (#1088) — never advise rotating a credential first.

    `verify=True` (the `saw audit --verify` opt-in) content-scans a lone weak *directory*
    to turn it into an actual verdict (#1221): CONFIRMED worm markers inside → `warning`; scanned
    clean → a reassuring `info`; too large / unreadable → the same honest 'verify it yourself'."""
    strong, weak = _host_artifacts()
    weak_descs = [desc for desc, _ in weak]
    found = strong + weak_descs
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
    # Exactly one weak indicator, no strong. With --verify we can content-scan it.
    if verify:
        graded = _verify_weak_artifact(weak[0])
        if graded is not None:
            return graded
    return [HygieneIssue(          # a single WEAK, unverified indicator — surface honestly, don't accuse
        id="host-drop-artifact-weak",
        severity="info",
        title="Unusual file/dir on this host (weak supply-chain indicator)",
        detail="Found: " + "; ".join(found) + ". This is a WEAK, single indicator — a location the "
               "worm sometimes uses, but a manual `npm install`/`pip` run from your home dir makes "
               "the same thing. Existence alone can't tell them apart, so on its own it is not "
               "evidence of malware.",
        remediation="Verify it's yours: inspect the path (e.g. its package.json / contents) for "
                    "anything you don't recognize, and recall whether you created it. If it is NOT "
                    "yours, treat as possible compromise — isolate the host, neutralize any "
                    f"persistence, and rotate credentials LAST ({_WIPER_NOTE}). Or run "
                    "`saw audit --verify` to content-scan it.",
    )]


def _verify_weak_artifact(item: tuple[str, Path]) -> list[HygieneIssue] | None:
    """Content-scan one lone weak artifact and grade honestly (#1221). Returns None when the artifact
    is not a scannable directory (e.g. a lone `get-pip.py` file) so the caller falls back to the
    honest 'verify it yourself' info. The scanner import is LOCAL so the default audit (no
    `--verify`) never pulls the scan engine in."""
    desc, path = item
    try:
        is_dir = path.is_dir()
    except OSError:
        is_dir = False
    if not is_dir:
        return None
    from stayawake.bots.security.verify import verify_dir   # opt-in only — keep the default audit lean
    v = verify_dir(path)
    if v.has_markers:
        return [HygieneIssue(
            id="host-artifact-content-infected",
            severity="warning",
            title="Content scan found worm markers inside a host artifact",
            detail=f"Scanned {path} ({v.files} files) and found CONFIRMED malware markers: "
                   f"{', '.join(v.markers)}. This is no longer a weak indicator — there is worm "
                   "loader code on this host.",
            remediation="Treat as a LIVE compromise. Isolate the host, neutralize any persistence, "
                        "rebuild from a known-clean image, and rotate credentials LAST — "
                        f"{_WIPER_NOTE}.",
        )]
    if v.scanned_clean:
        return [HygieneIssue(
            id="host-artifact-scanned-clean",
            severity="info",
            title="Unusual dir on this host — content-scanned, no worm markers",
            detail=f"{desc} — scanned {v.files} files inside and found no confirmed malware markers. "
                   "Consistent with a normal npm tree in an unusual place, not evidence of the worm.",
            remediation="Low concern. Still confirm you created it (recall the install); if you did "
                        f"NOT, isolate the host and rotate credentials LAST ({_WIPER_NOTE}).",
        )]
    # Bounded out (too large), incomplete coverage, or a read gap — we did NOT fully look inside,
    # so stay honest (never downgrade concern on a tree we couldn't fully read).
    if v.too_large:
        reason = "it is too large to auto-scan"
    elif v.partial:
        reason = "part of it could not be read (an oversize file, or a symlink leaving the folder)"
    else:
        reason = f"it could not be fully scanned ({v.error})"
    return [HygieneIssue(
        id="host-drop-artifact-weak",
        severity="info",
        title="Unusual file/dir on this host (weak supply-chain indicator)",
        detail=f"Found: {desc}. WEAK, single indicator — {reason}, so it was not content-verified. "
               "A manual `npm install` makes the same thing; existence alone is not evidence of "
               "malware.",
        remediation="Verify it's yours: inspect the path (e.g. its package.json / contents), and "
                    "recall whether you created it. If it is NOT yours, isolate the host and rotate "
                    f"credentials LAST ({_WIPER_NOTE}).",
    )]


