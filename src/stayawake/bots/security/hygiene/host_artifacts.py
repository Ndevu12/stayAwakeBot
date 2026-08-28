#!/usr/bin/env python3
"""Host filesystem drop-artifacts — staged ingress tooling + data bundled for exfil (T1105/T1074)."""
from __future__ import annotations

import getpass
import os
import socket
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from stayawake.utils.pathsafe import canonical_id

from .models import HygieneIssue, _WIPER_NOTE

#
# drop-files this wave stages on a developer host — downloaded tooling and stolen data bundled
# before exfil. Some are weak on their own (a stray ~/.node_modules, an npm cache), so a LONE weak
# indicator is `info`; a strong, specific IoC or a corroborated set (>=2) is a `warning`. A positive
# Every probe is a read-only stat/listdir and degrades to nothing when a path is absent/unreadable.

KIND_GLOBAL_FOLDER = "node-global-folder"
KIND_NPM_CACHE = "npm-cache"
KIND_PIP_BOOTSTRAP = "pip-bootstrap"

_TOOLCHAIN_THAT_LEAVES_EACH_KIND = {KIND_GLOBAL_FOLDER: "node", KIND_NPM_CACHE: "node",
                                    KIND_PIP_BOOTSTRAP: "python"}


def _toolchains_represented(weak: list[tuple[str, Path, str]]) -> set[str]:
    """How many separate acts these indicators are evidence of. One command leaves a resolution path
    and a cache together, so both are one act; a second toolchain is a second act."""
    return {_TOOLCHAIN_THAT_LEAVES_EACH_KIND.get(kind, kind) for _desc, _path, kind in weak}


def _distinct_dirs(paths: list[Path]) -> list[Path]:
    """`paths` with aliases of one real directory collapsed, in a stable order."""
    out: list[Path] = []
    seen: set = set()
    for p in paths:
        ident = canonical_id(p)
        if ident not in seen:
            seen.add(ident)
            out.append(p)
    return sorted(out, key=str)


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


def _host_artifacts() -> tuple[list[str], list[tuple[str, Path, str]]]:
    """Return (strong, weak) detected host-IoC drop artifacts. `strong` are descriptions; `weak` are
    (description, path, kind) triples: the path so a caller can content-scan it, the kind so grading
    can ask what KINDS of evidence there are rather than how many strings were appended."""
    home = Path.home()
    tmp_dirs = _distinct_dirs([Path("/tmp"), Path(tempfile.gettempdir())])
    strong: list[str] = []
    weak: list[tuple[str, Path, str]] = []

    def _present(p: Path) -> bool:
        try:
            return p.exists()
        except OSError:
            return False

    def _present_dir(p: Path) -> bool:
        """Existence is not the test when the indicator is described as a TREE. A regular file at
        `~/.node_modules` is what prevention guidance tells operators to CREATE, to deny the staging
        path — so accepting it reported the hardened host as the compromised one."""
        try:
            return p.is_dir()
        except OSError:
            return False

    # Weak drop-files — a single low-confidence indicator each. Described NEUTRALLY (not "payload"):
    # each has a mundane explanation as well as the worm one, and existence alone can't tell them
    # apart — so we surface, we don't accuse. The path rides along so `--verify` can content-scan it.
    #
    # The mundane cause of `~/.node_modules` is Node's own resolution, not a stray install: an
    # `npm install` in $HOME creates `~/node_modules`, with no dot, so naming that as the way to
    # self-clear pointed at a path this probe never looks at.
    # EVERY entry of Node's GLOBAL_FOLDERS, not a subset. Node resolves a global module through
    # `~/.node_modules`, `~/.node_libraries`, then `$PREFIX/lib/node`; covering some of them draws the
    # line exactly where an attacker reading the same documentation steps over it. The prefix entry is
    # reachable WITHOUT root on a Homebrew Mac, where `/usr/local` is user-owned, so it is not a
    # root-only location the user-level worm model can dismiss.
    for location in _global_folders():
        if _present_dir(location):
            weak.append((f"{location} (a node module tree in a global resolution path — "
                         "unusual location)", location, KIND_GLOBAL_FOLDER))
    for t in tmp_dirs:
        if _present(t / ".npm"):
            weak.append((f"{t}/.npm", t / ".npm", KIND_NPM_CACHE))
        if _present(t / "get-pip.py"):
            weak.append((f"{t}/get-pip.py", t / "get-pip.py", KIND_PIP_BOOTSTRAP))

    tag = _host_user_tag()
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



def _global_folders() -> list[Path]:
    """Node's GLOBAL_FOLDERS, resolved on ANY platform — every path the runtime loads a global
    module from.

    The two home-relative entries are the same everywhere. `$PREFIX` is Node's install prefix: read
    from the environment when set, and otherwise the platform's documented defaults, because a
    POSIX-only list would leave the equivalent Windows locations uncovered — the same partial
    coverage this probe exists to remove. `/usr/local` and `%APPDATA%` are user-writable on ordinary
    installs, so the prefix entry is reachable without administrator rights."""
    home = Path.home()
    roots: list[Path] = []
    for var in ("PREFIX", "NODE_PREFIX", "npm_config_prefix"):
        if os.environ.get(var):
            roots.append(Path(os.environ[var]))
    if sys.platform.startswith("win"):
        for var in ("APPDATA", "ProgramFiles", "ProgramW6432", "LOCALAPPDATA"):
            if os.environ.get(var):
                roots += [Path(os.environ[var]) / "npm", Path(os.environ[var]) / "nodejs"]
    else:
        roots += [Path("/usr/local"), Path("/usr"), Path("/opt/homebrew"), Path("/opt/local")]
    folders = [home / ".node_modules", home / ".node_libraries"]
    folders += [root / "lib" / "node" for root in roots]
    return _distinct_dirs(folders)


def _corroborated_issue(found: list[str], *, active: bool) -> HygieneIssue:
    """The corroborated finding. `active` distinguishes evidence of a live implant from staging in
    more than one place: same severity and the same rotation gate either way, different claim."""
    if active:
        return HygieneIssue(
            id="host-drop-artifacts",
            severity="warning",
            title="Host filesystem artifacts consistent with a supply-chain payload",
            detail="Found: " + "; ".join(found) + ". These are ingress-tooling / data-staging "
                   "drop-files (T1105/T1074) this wave leaves on a developer host.",
            remediation="Do NOT rotate credentials first — treat as possible LIVE compromise. "
                        "Isolate the host, neutralize any persistence, rebuild from a known-clean "
                        f"image, and rotate credentials LAST — {_WIPER_NOTE}.",
        )
    return HygieneIssue(
        id="host-drop-artifacts-staging",
        severity="warning",
        title="The same staging artifact in more than one location on this host",
        detail="Found: " + "; ".join(found) + ". One kind of staging drop-file (T1105/T1074) in "
               "more than one real directory. Ordinary tooling puts it in one place, not several.",
        remediation="Inspect each location before trusting it, and do NOT rotate any credential "
                    "yet — see the note above.",
    )


def _escalate_with_scan(issue: HygieneIssue, weak: list[tuple[str, Path, str]]) -> HygieneIssue:
    """Content-scan every corroborated candidate; markers may only ESCALATE.

    The existence finding is built first and returned unchanged unless a scan finds payload, so a
    clean or failed scan can never lower a corroborated grade. `_verify_weak_artifact` scanned
    `weak[0]` alone, which let a clean first location mask an infected second.
    """
    for item in weak:
        graded, failure = _scan_or_reason(item[:2])
        if failure is not None:                            # an aborted scan must not lose the finding
            return replace(issue, detail=issue.detail +
                           f" (a content scan of {item[1]} could not complete: "
                           f"{failure} — the artifacts above were still found.)")
        for g in graded or []:
            if g.id == "host-artifact-content-infected":
                return g
    return issue


def check_host_artifacts(verify: bool = False) -> list[HygieneIssue]:
    """Detect host filesystem drop-files this wave stages on a developer workstation.

    FP-bounded: a strong/specific IoC or a corroborated set (>=2) is a `warning`; a lone weak
    indicator is `info`. SAFETY: a positive means persistence may be live, so the remediation
    follows the rotate-LAST order — never advise rotating a credential first.

    Corroboration counts ENTRIES, whose roots are already identity-deduped — collapsing aliases
    again at the artifact level would let an attacker suppress it by symlinking a second drop at
    the first.

    `verify=True` (the `saw audit --verify` opt-in) content-scans a lone weak *directory*
    to turn it into an actual verdict: CONFIRMED worm markers inside → `warning`; scanned
    clean → a reassuring `info`; too large / unreadable → the same honest 'verify it yourself'."""
    strong, weak = _host_artifacts()
    weak_descs = [desc for desc, _, _ in weak]
    found = strong + weak_descs
    if not found:
        return []
    corroborated = bool(strong) or len(weak) >= 2

    if corroborated:
        active = bool(strong) or len(_toolchains_represented(weak)) >= 2
        issue = _corroborated_issue(found, active=active)
        if verify:
            issue = _escalate_with_scan(issue, weak)
        return [issue]
    if verify:
        graded, _failure = _scan_or_reason(weak[0][:2])
        if graded is not None:
            return graded
    return [HygieneIssue(          # a single WEAK, unverified indicator — surface honestly, don't accuse
        id="host-drop-artifact-weak",
        severity="info",
        title="Unusual file/dir on this host (weak supply-chain indicator)",
        # The benign cause is NAMED, not merely asserted: a reader cannot clear the finding
        # themselves if we blame a command that could not have produced the path.
        detail="Found: " + "; ".join(found) + ". A weak, single indicator: ordinary tooling creates "
               "these too (Node's GLOBAL_FOLDERS, a pip bootstrap), so on its own this is not "
               "evidence of malware.",
        remediation="Check whether it is yours (inspect the contents). If not, isolate the host and "
                    f"rotate credentials LAST: {_WIPER_NOTE}. `saw audit --verify` content-scans it.",
    )]


def _scan_or_reason(item: tuple[str, Path]) -> tuple[list[HygieneIssue] | None, str | None]:
    """(findings, why it could not run). ONE place the content scan's failure is caught, so both
    callers inherit it — the lone-indicator path did not, and an aborted scan escaped from there."""
    try:
        return _verify_weak_artifact(item), None
    except (Exception, KeyboardInterrupt) as exc:
        return None, type(exc).__name__


def _verify_weak_artifact(item: tuple[str, Path]) -> list[HygieneIssue] | None:
    """Content-scan one lone weak artifact and grade honestly. Returns None when the artifact
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
                   f"{', '.join(v.markers)}. This is no longer a weak indicator: there is worm "
                   "code on this host.",
            remediation="Treat as a LIVE compromise. Isolate the host, neutralize any persistence, "
                        "rebuild from a known-clean image, and rotate credentials LAST — "
                        f"{_WIPER_NOTE}.",
        )]
    # Markers may only PROMOTE this finding, never lower it. Measured on a real incident'''s staged
    # tree: 488 files fully read, no archives, nothing to find — the loader lived only in argv.
    # Short sentences, plain words: the previous single sentence nested parentheses, said "not read"
    # twice, and ended on the reassuring half so the warning read as an all-clear.
    _NOT_CLEARED = ("That does not clear it: the harmful part can be the program that used these "
                    "files, not the files themselves.")
    if v.scanned_clean:
        outcome = f"A content scan found no worm markers. {_NOT_CLEARED}"
    elif v.too_large:
        outcome = "It is too large to scan automatically, so its contents were not checked."
    elif v.partial and v.unread:
        outcome = (f"Not everything was read: {'; '.join(v.unread)}. A content scan of the rest "
                   f"found no worm markers. {_NOT_CLEARED}")
    elif v.partial:
        outcome = "Part of it could not be read, so its contents were not fully checked."
    else:
        outcome = f"It could not be fully scanned ({v.error}), so its contents were not checked."
    return [HygieneIssue(
        id="host-drop-artifact-weak",
        severity="info",
        title="Unusual file/dir on this host (weak supply-chain indicator)",
        detail=f"Found: {desc}. A weak, single indicator: ordinary tooling creates these too, so on "
               f"its own this is not evidence of malware. {outcome}",
        remediation="Check whether you created it (inspect its contents, and recall the install). "
                    f"If it is NOT yours, isolate the host and rotate credentials LAST: {_WIPER_NOTE}.",
    )]
