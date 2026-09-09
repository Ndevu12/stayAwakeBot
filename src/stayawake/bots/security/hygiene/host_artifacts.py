#!/usr/bin/env python3
"""Host filesystem drop-artifacts — staged ingress tooling + data bundled for exfil (T1105/T1074)."""
from __future__ import annotations

import getpass
import os
import pathlib
import socket
import stat
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from stayawake.utils import hostdenial
from stayawake.utils.pathsafe import canonical_id, grade

from .models import (HOST_ARTIFACT_SCAN_BLOCKED_ID, HygieneIssue, _WIPER_NOTE,
                     could_not_read)

#
# drop-files this wave stages on a developer host — downloaded tooling and stolen data bundled
# before exfil. Some are weak on their own (a stray ~/.node_modules, an npm cache), so a LONE weak
# indicator is `info`; a strong, specific IoC or a corroborated set (>=2) is a `warning`. A path that
# exists but cannot be read is reported, not treated as clean.

KIND_GLOBAL_FOLDER = "node-global-folder"
KIND_NPM_CACHE = "npm-cache"
KIND_PIP_BOOTSTRAP = "pip-bootstrap"

_TOOLCHAIN_THAT_LEAVES_EACH_KIND = {KIND_GLOBAL_FOLDER: "node", KIND_NPM_CACHE: "node",
                                    KIND_PIP_BOOTSTRAP: "python"}


_TOOL_OWN_BOOKKEEPING = {
    KIND_NPM_CACHE: ("_cacache", "_logs", "_npx", "_locks", "_update-notifier-last-checked"),
}


def _holds_something_staged(path: Path, kind: str) -> bool:
    """Whether anything is staged at `path`, ignoring the entries its own tool writes.

    Asked only of a kind an ordinary tool creates empty. `NPM_CONFIG_CACHE` under a temp directory
    is what the usual CI images and the Lambda Node runtimes set, so the cache existing says
    nothing; a global resolution path is different, and its own comment above says why.
    """
    if kind not in _TOOL_OWN_BOOKKEEPING:
        return True
    try:
        if not path.is_dir():
            return True
        return any(child.name not in _TOOL_OWN_BOOKKEEPING[kind] for child in path.iterdir())
    except OSError:
        return True


def _staged(weak: list[tuple]) -> list[tuple]:
    """The indicators that hold something."""
    return [item for item in weak if _holds_something_staged(item[1], item[2])]


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


def _unreadable(unread: list[Path], path: Path) -> bool:
    if grade(path) == "unverified":
        unread.append(path)
        return True
    return False


def _first_child_named(directory: Path, prefix: str, unread: list[Path]) -> Path | None:
    state = grade(directory)
    if state == "unverified":
        unread.append(directory)
        return None
    if state != "ok":
        return None
    try:
        for entry in sorted(directory.iterdir()):
            if entry.name.startswith(prefix):
                return entry
    except OSError:
        unread.append(directory)
    return None


def _sideloaded_python_dir(unread: list[Path]) -> Path | None:
    """A Windows `%LOCALAPPDATA%\\…\\Python3127\\` dir carrying the sideloaded interpreter/archiver
    (python.exe/python.zip/python.7z/7zr.exe). No-op off Windows (LOCALAPPDATA unset)."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return None
    sideload = {"python.exe", "python.zip", "python.7z", "7zr.exe"}
    for pattern in ("Python3127", "*/Python3127", "*/*/Python3127"):   # bounded, not a full walk
        try:
            for d in Path(local).glob(pattern):
                if _unreadable(unread, d):
                    continue
                try:
                    if d.is_dir() and {f.name.lower() for f in d.iterdir()} & sideload:
                        return d
                except OSError:
                    unread.append(d)
                    continue
        except OSError:
            unread.append(Path(local))
            break
    return None


def _staged_secret_scanner(dirs, unread: list[Path]) -> Path | None:
    """A trufflehog secret-scanner BINARY staged in a cache/temp dir (T1588.002/T1552). Matches a
    FILE only — trufflehog's own `~/.cache/trufflehog` DIR (a legit user's cache) is not a hit."""
    for d in dirs:
        for name in ("trufflehog", "trufflehog.exe"):
            p = d / name
            if _unreadable(unread, p):
                continue
            try:
                if p.is_file():
                    return p
            except OSError:
                unread.append(p)
    return None


def _host_artifacts() -> tuple[list[str], list[tuple[str, Path, str]], list[Path], list[Path]]:
    """Return (strong, weak, unread, controlled). `weak` are (description, path, kind) triples;
    `controlled` are the locations a host control already holds."""
    home = Path.home()
    tmp_dirs = _distinct_dirs([Path("/tmp"), Path(tempfile.gettempdir())])
    strong: list[str] = []
    weak: list[tuple[str, Path, str]] = []
    unread: list[Path] = []
    controlled: list[Path] = []

    def _present(p: Path) -> bool:
        if _unreadable(unread, p):
            return False
        try:
            return p.exists()
        except OSError:
            unread.append(p)
            return False

    def _present_dir(p: Path) -> bool:
        if _unreadable(unread, p):
            return False
        try:
            return p.is_dir()
        except OSError:
            unread.append(p)
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
    # A denial is recognised by its SHAPE, not by a marker: an empty directory nothing can write
    # into is what the control IS, so no mark is needed and none is possible — a marker inside it
    # would end the emptiness that does the work. Either grade counts, because either is this
    # tool's own work; how strong each one is belongs in what `harden` says about it, not in
    # whether this probe accuses it.
    #
    # Emptiness is NOT the discriminator, and using it lost a real signal: the indicator here is
    # that the location EXISTS AT ALL. Nothing ordinary creates one — an `npm install` in $HOME
    # makes `node_modules` with no dot — so an empty one is still something that was put there.
    for location in _global_folders():
        if hostdenial.held_by_us(location):
            controlled.append(location)
            continue
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
        for d in (home, home / ".npm", *tmp_dirs, pathlib.Path.cwd()):
            match = _first_child_named(d, tag, unread)
            if match is not None:
                strong.append(f"{match} (<host>$<user> exfil staging archive)")
                break
    sideloaded = _sideloaded_python_dir(unread)
    if sideloaded is not None:
        strong.append(f"{sideloaded} (sideloaded Python3127 interpreter)")
    scanner = _staged_secret_scanner((home / ".cache", home / ".npm", *tmp_dirs), unread)
    if scanner is not None:
        strong.append(f"{scanner} (staged secret-scanner binary)")
    return strong, weak, unread, controlled



def _npm_prefix_roots() -> list[Path]:
    """Node's install prefixes on this host, in resolution order: those the environment declares,
    then the platform's documented defaults."""
    declared: list[Path] = []
    for var in ("PREFIX", "NODE_PREFIX", "npm_config_prefix"):
        named = _usable_prefix(os.environ.get(var))
        if named is not None:
            declared.append(named)
    roots: list[Path] = []
    if sys.platform.startswith("win"):
        for var in ("APPDATA", "ProgramFiles", "ProgramW6432", "LOCALAPPDATA"):
            if os.environ.get(var):
                roots += [Path(os.environ[var]) / "npm", Path(os.environ[var]) / "nodejs"]
    else:
        roots += [Path("/usr/local"), Path("/usr"), Path("/opt/homebrew"), Path("/opt/local")]
    return declared + roots


def _global_folders() -> list[Path]:
    """Node's GLOBAL_FOLDERS, resolved on ANY platform — every path the runtime loads a global
    module from.

    The two home-relative entries are the same everywhere. `$PREFIX` is Node's install prefix: read
    from the environment when set, and otherwise the platform's documented defaults, because a
    POSIX-only list would leave the equivalent Windows locations uncovered — the same partial
    coverage this probe exists to remove. `/usr/local` and `%APPDATA%` are user-writable on ordinary
    installs, so the prefix entry is reachable without administrator rights."""
    home = Path.home()
    # The two home entries are targeted whether or not they exist — absent is the state a payload
    # creates them from. A PREFIX entry is different: if the prefix root is not on this machine,
    # nothing is installed there, so it is not a path the runtime resolves through and there is
    # nothing to find or to deny. Naming it anyway would have a control create the prefix of a
    # package manager the host does not have.
    # Present or not: this answers where the runtime looks, and what a control may CREATE is that
    # control's decision. Filtering here starved the probe of locations it enumerates for coverage.
    folders = [home / ".node_modules", home / ".node_libraries"]
    folders += [root / "lib" / "node" for root in _npm_prefix_roots()]
    return _distinct_dirs(folders)


def _usable_prefix(raw: str | None) -> Path | None:
    """A prefix this may act on, or None.

    Absolute and already normalised, or nothing. A relative prefix resolves against the working
    directory — `PREFIX=.` had a host-level control create an immutable `lib/node` inside whatever
    repository it was run from. A `..` is worse than untidy: the kernel resolves it while walking,
    so the per-component check that exists to refuse a planted symlink never sees the link.
    """
    if not raw or not raw.strip():
        return None
    if os.path.normpath(raw) != raw or not os.path.isabs(raw):
        return None
    return Path(raw)


def _corroborated_issue(found: list[str], *, active: bool) -> HygieneIssue:
    """The corroborated finding. `active` distinguishes evidence of a live implant from staging in
    more than one place: same severity and the same rotation gate either way, different claim."""
    if active:
        return HygieneIssue(
            id="host-drop-artifacts",
            severity="warning",
            title="Files this wave leaves on a developer host are on this machine",
            detail=f"{len(found)} of them. Treat as a possible live compromise.",
            remediation="Isolate this machine, run `saw harden`, and rotate credentials LAST — "
                        f"{_WIPER_NOTE}.",
        )
    return HygieneIssue(
        id="host-drop-artifacts-staging",
        severity="warning",
        title="The same staging artifact is in more than one place on this host",
        detail=f"{len(found)} places. Ordinary tooling puts one there, not several.",
        remediation="Run `saw audit --verify`, and do NOT rotate any credential yet.",
    )


def _outside_a_control_issue(found: list[str]) -> HygieneIssue:
    """A lone indicator that keeps its grade when a control covers a sibling location.

    Applying a control removes the location it covers from this evidence, which on its own would
    make a host with one remaining artifact read more safely after the control than before it. The
    remaining location is the one the control did not cover, and that is what it says."""
    return HygieneIssue(
        id="host-drop-artifact-outside-a-control",
        severity="warning",
        title="A global resolution path here is not covered by a control",
        detail="A control covers another on this machine; this one was left as it stood.",
        remediation="Run `saw harden`, and do NOT rotate any credential yet.",
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
    strong, weak, unread, controlled = _host_artifacts()
    weak_descs = [desc for desc, _, _ in weak]
    found = strong + weak_descs
    extra = [could_not_read(dict.fromkeys(unread))] if unread else []
    if not found:
        return extra
    staged = _staged(weak)
    corroborated = bool(strong) or len(staged) >= 2

    if corroborated:
        active = bool(strong) or len(_toolchains_represented(staged)) >= 2
        issue = _corroborated_issue(found, active=active)
        if verify:
            issue = _escalate_with_scan(issue, weak)
        return [issue] + extra
    if controlled and staged:
        issue = _outside_a_control_issue([desc for desc, _p, _k in staged])
        if verify:
            issue = _escalate_with_scan(issue, staged)
        return [issue] + extra
    if verify:
        graded, failure = _scan_or_reason(weak[0][:2])
        if graded is not None:
            return graded + extra
        if failure is not None:
            extra = [_scan_blocked_issue(weak[0][1], failure)] + extra
    return [HygieneIssue(
        id="host-drop-artifact-weak",
        severity="info",
        title="Something unusual is on this host (weak indicator)",
        detail="Ordinary tooling creates these too — Node's GLOBAL_FOLDERS, a pip bootstrap.",
        remediation="Run `saw audit --verify`.",
    )] + extra


def _scan_blocked_issue(path: Path, failure: str) -> HygieneIssue:
    """The content scan `--verify` promised and did not deliver, on this surface.

    `_scan_or_reason` answers None for both "nothing scannable here" and "the scan blew up";
    conflated, the second printed the fallback whose own advice is to run `--verify`.
    """
    return HygieneIssue(
        id=HOST_ARTIFACT_SCAN_BLOCKED_ID,
        severity="unknown",
        title="The content scan asked for did not run",
        detail=f"The scan did not run ({failure}), so the contents are UNKNOWN, not clean.",
        remediation="Resolve what stopped it and re-run. Do not rotate credentials yet.",
    )


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
    `--verify`) never pulls the scan engine in.

    Only `scanned_clean` clears a directory: two of the other verdicts return before the scanner
    runs at all, so none of them may be worded as a scan that found nothing."""
    desc, path = item
    if grade(path) == "unverified":
        return [could_not_read([path])]
    try:
        is_dir = path.is_dir()
    except OSError:
        return [could_not_read([path])]
    if not is_dir:
        return None
    from stayawake.bots.security.verify import verify_dir   # opt-in only — keep the default audit lean
    v = verify_dir(path)
    if v.has_markers:
        return [HygieneIssue(
            id="host-artifact-content-infected",
            severity="warning",
            title="Content scan found worm markers inside a host artifact",
            detail=f"{len(v.markers)} confirmed marker(s) in {v.files} files. There is worm code "
                   "on this host.",
            remediation="Treat as a LIVE compromise. Isolate this machine and rotate credentials "
                        f"LAST — {_WIPER_NOTE}.",
        )]
    # Markers may only PROMOTE this finding, never lower it. Measured on a real incident'''s staged
    # tree: 488 files fully read, no archives, nothing to find — the loader lived only in argv.
    # Short sentences, plain words: the previous single sentence nested parentheses, said "not read"
    # twice, and ended on the reassuring half so the warning read as an all-clear.
    _NOT_CLEARED = "The program that used them can be the harmful part."
    if v.scanned_clean:
        outcome = f"A scan found no markers. {_NOT_CLEARED}"
    elif v.too_large:
        outcome = "Too large to scan."
    elif v.partial and v.unread:
        outcome = f"It was not fully scanned: {'; '.join(v.unread)}. {_NOT_CLEARED}"
    elif v.partial:
        outcome = "Part of it was unreadable."
    else:
        outcome = "It could not be scanned."
    return [HygieneIssue(
        id="host-drop-artifact-weak",
        severity="info",
        title="Something unusual is on this host (weak indicator)",
        detail=f"Ordinary tooling creates these. {outcome}",
        remediation="Confirm you created it. If not, isolate this machine and rotate "
                    "credentials LAST.",
    )]
