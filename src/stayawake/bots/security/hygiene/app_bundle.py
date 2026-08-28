#!/usr/bin/env python3
"""An installed application's own JavaScript — the modules it loads at startup.

Not a dependency: no manifest lists it, no lockfile covers it, and removing `node_modules` never
reaches it. Grading rationale, corpus and limits: `Ndevu12/saw#218`."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from stayawake.utils.pathsafe import canonical_id

from .models import HygieneIssue, _WIPER_NOTE

_JS_SUFFIXES = (".js", ".mjs", ".cjs")

_PAD_MIN = 50
_BODY_MIN = 40
_TRAILING_LINES_MAX = 12

_PAD_BYTES = (b" ", b"\t", b"\x0b", b"\x0c")
_PAD_NBSP = " ".encode()

_FIRST_READ_BYTES = 4096
_SUBSEQUENT_READ_BYTES = 65536
_MAX_TAIL_BYTES = 64 * 1024 * 1024
_MAX_FILES_PER_ROOT = 20_000
_MAX_DATA_DIRECTORY_DEPTH = 7

_BUNDLE_LEAVES = ("resources/app", "resources/app.asar.unpacked",
                  "Contents/Resources/app", "Contents/Resources/app.asar.unpacked")
_BUNDLE_WILDCARD_DEPTHS = ("", "*/", "*/*/", "*/*/*/")
_LEAF_BURIED_DEEPER_BY_PACKAGING = {
    "flatpak": ("*/*/*/*/files/resources/app", "*/*/*/*/files/*/resources/app"),
    "snap": ("*/current/resources/app", "*/current/usr/lib/*/resources/app"),
    "appimage": ("*/squashfs-root/resources/app", "squashfs-root/resources/app"),
}


def _bundle_bases() -> list[Path]:
    home = Path.home()
    if sys.platform == "darwin":
        return [Path("/Applications"), home / "Applications"]
    if sys.platform.startswith("win"):
        return [Path(os.environ[var]) for var in
                ("LOCALAPPDATA", "PROGRAMFILES", "PROGRAMW6432", "APPDATA")
                if os.environ.get(var)]
    return [Path(p) for p in ("/opt", "/usr/lib", "/usr/share", "/usr/local/lib")] + [
        home / ".local" / "share", home / "opt"]


def _packaged_bases() -> list[tuple[Path, tuple[str, ...]]]:
    """Bases whose layout buries the bundle leaf deeper than the wildcard depths reach."""
    home = Path.home()
    if sys.platform in ("darwin",) or sys.platform.startswith("win"):
        return []
    return [(Path("/var/lib/flatpak/app"), _LEAF_BURIED_DEEPER_BY_PACKAGING["flatpak"]),
            (home / ".local" / "share" / "flatpak" / "app", _LEAF_BURIED_DEEPER_BY_PACKAGING["flatpak"]),
            (Path("/snap"), _LEAF_BURIED_DEEPER_BY_PACKAGING["snap"]),
            (home / "Applications", _LEAF_BURIED_DEEPER_BY_PACKAGING["appimage"]),
            (home / "Apps", _LEAF_BURIED_DEEPER_BY_PACKAGING["appimage"])]


def _data_bases() -> list[Path]:
    """Where an application keeps a per-version copy of its own modules, outside its bundle."""
    home = Path.home()
    if sys.platform == "darwin":
        return [home / "Library" / "Application Support"]
    if sys.platform.startswith("win"):
        return [Path(os.environ[var]) for var in ("APPDATA", "LOCALAPPDATA")
                if os.environ.get(var)]
    return [home / ".config"]


def app_bundle_js_roots() -> list[tuple[Path, int | None]]:
    """(tree, depth bound) for every installed application's own JavaScript, deduplicated by
    filesystem identity — `/Applications/Applications` is a symlink to `/Applications` on macOS,
    which yields each bundle twice, and `Contents/Resources` matches `Contents/resources` on a
    case-insensitive volume. A bundle tree is read whole; a data directory is read to a depth."""
    patterns = [f"{depth}{leaf}" for depth in _BUNDLE_WILDCARD_DEPTHS for leaf in _BUNDLE_LEAVES]
    candidates: list[tuple[Path, list[str], int | None]] = [
        (base, patterns, None) for base in _bundle_bases()]
    candidates += [(base, list(globs), None) for base, globs in _packaged_bases()]
    candidates += [(base, ["*"], _MAX_DATA_DIRECTORY_DEPTH) for base in _data_bases()]
    roots: list[tuple[Path, int | None]] = []
    seen: set = set()
    for base, globs, depth in candidates:
        for pattern in globs:
            try:
                matches = sorted(base.glob(pattern))
            except OSError:
                continue
            for match in matches:
                try:
                    if not match.is_dir():
                        continue
                except OSError:
                    continue
                ident = canonical_id(match)
                if ident not in seen and not any(_within(match, r) for r, _d in roots):
                    seen.add(ident)
                    roots.append((match, depth))
    return roots


def _within(path: Path, root: Path) -> bool:
    """True when `path` is `root` or sits under it — a nested match is already covered by the walk,
    and re-rooting it would read the same modules again."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _indent(line: bytes) -> int:
    at = 0
    while at < len(line):
        if line[at:at + 1] in _PAD_BYTES:
            at += 1
        elif line[at:at + 2] == _PAD_NBSP:
            at += 2
        else:
            break
    return at


def _tail_lines(path: Path) -> tuple[list[bytes] | None, bool]:
    """(the file's last `_TRAILING_LINES_MAX` lines, whether they were established).

    `(None, False)` means they do not begin within `_MAX_TAIL_BYTES`, which the caller reports
    rather than counting as nothing found."""
    wanted = _TRAILING_LINES_MAX
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            if position < _PAD_MIN + _BODY_MIN:
                return [], True
            parts: list[bytes] = []
            newlines = read = 0
            while position > 0:
                step = min(_FIRST_READ_BYTES if not parts else _SUBSEQUENT_READ_BYTES, position)
                position -= step
                handle.seek(position)
                chunk = handle.read(step)
                parts.append(chunk)
                newlines += chunk.count(b"\n")
                read += step
                if newlines > wanted:
                    break
                if read > _MAX_TAIL_BYTES:
                    return None, False
            tail = b"".join(reversed(parts))
    except OSError:
        return [], True
    return tail.rstrip(b"\r\n").split(b"\n")[-wanted:], True


def _appended_line(lines: list[bytes]) -> tuple[int, int] | None:
    """(pad, content) of the first of those lines that opens with a long pad and carries content."""
    for index, raw in enumerate(lines):
        line = raw.rstrip(b"\r")
        pad = _indent(line)
        if pad < _PAD_MIN:
            continue
        content_characters = sum(len(other.decode("utf-8", "replace").strip())
                                 for other in lines[index:])
        if content_characters >= _BODY_MIN:
            return pad, content_characters
    return None


def _scan_markers(directory: Path) -> list[str]:
    """CONFIRMED markers in one module's own directory, or []. The engine import is LOCAL, and the
    scan is opt-in because it is slow — see `saw#218` for the measurement."""
    try:
        from stayawake.bots.security.verify import verify_dir
        return list(verify_dir(directory).markers)
    except (Exception, KeyboardInterrupt):
        return []


def check_app_bundles(verify: bool = False) -> list[HygieneIssue]:
    """Grade the JavaScript an installed application loads at startup.

    The shape alone is `info`: a build emits neither the pad nor a file that ends right after one,
    but a user-patched bundle is a real thing. `verify=True` (`saw audit --verify`) content-scans
    the module's own directory, and CONFIRMED markers corroborate it into an active foothold — two
    findings rather than one with a hedge, so the rotation gate follows evidence, not shape."""
    issues: list[HygieneIssue] = []
    unbounded = truncated = 0
    walked: set = set()
    for root, max_depth in app_bundle_js_roots():
        examined = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
            here = canonical_id(Path(dirpath))            # followlinks=True can revisit and loop
            if here in walked:
                dirnames[:] = []
                continue
            walked.add(here)
            if max_depth is not None and _depth(root, Path(dirpath)) >= max_depth:
                dirnames[:] = []          # a design boundary, stated in the docs — not a truncation
            for name in sorted(filenames):
                if not name.lower().endswith(_JS_SUFFIXES):
                    continue
                if examined >= _MAX_FILES_PER_ROOT:
                    truncated += 1
                    break
                examined += 1
                module = Path(dirpath) / name
                lines, established = _tail_lines(module)
                if not established:
                    unbounded += 1
                    continue
                shape = _appended_line(lines) if lines else None
                if shape is None:
                    continue
                markers = _scan_markers(module.parent) if verify else []
                issues.append(_finding(module, *shape, markers))
            if examined >= _MAX_FILES_PER_ROOT:
                break                      # this tree only — the next application still gets read
    note = _unexamined_note(unbounded, truncated)
    return issues + ([note] if note else [])


def _depth(root: Path, directory: Path) -> int:
    try:
        return len(directory.relative_to(root).parts)
    except ValueError:
        return 0


def _unexamined_note(unbounded: int, truncated: int) -> HygieneIssue | None:
    """What the walk did NOT read. A bound that is not reported reads as coverage of what it cut."""
    parts: list[str] = []
    if truncated:
        parts.append(f"{truncated} trees hold more modules than one audit reads")
    if unbounded:
        parts.append(f"{unbounded} do not end within the lookback")
    if not parts:
        return None
    return HygieneIssue(
        id="app-bundle-partly-examined",
        severity="info",
        title="Some application modules were not examined",
        detail="Not every module an installed application loads was read: " + "; ".join(parts) + ".",
        remediation="Read them by hand, or reinstall the applications they belong to.",
    )


def _finding(module: Path, pad: int, body: int, markers: list[str]) -> HygieneIssue:
    if markers:
        return HygieneIssue(
            id="app-bundle-payload",
            severity="warning",
            title="Worm markers inside an installed application's own JavaScript",
            detail=f"{module} looks modified, and a scan of its directory is CONFIRMED: "
                   f"{', '.join(markers)}.",
            remediation="Treat as a LIVE compromise: isolate the host, reinstall the application, "
                        f"rotate credentials LAST — {_WIPER_NOTE}.",
        )
    return HygieneIssue(
        id="app-bundle-appended-module",
        severity="info",
        title="An application module looks modified",
        detail=f"{module} carries content its build would not have produced. "
               "`saw audit --verify` looks harder at it.",
        remediation="Compare it against the vendor's published copy, or reinstall the application. "
                    "If it is not theirs, isolate this host.",
    )
