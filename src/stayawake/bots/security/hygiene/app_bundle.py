#!/usr/bin/env python3
"""An installed application's own JavaScript — the modules it loads at startup.

Not a dependency: no manifest lists it, no lockfile covers it, and removing `node_modules` never
reaches it. Grading rationale, corpus and limits: `Ndevu12/saw#218`."""
from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils.pathsafe import canonical_id

from .models import HygieneIssue, APP_BUNDLE_MODULE_UNREADABLE_ID, APP_BUNDLE_SCAN_BLOCKED_ID, _WIPER_NOTE

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


def _note_unreadable(sink: list, root: Path):
    """`os.walk`'s default swallows a directory it cannot enumerate and yields nothing for it.

    Everything under such a directory disappears with no finding and no count — so an unreadable
    FILE failed closed while its unreadable PARENT failed open, and anything able to write a module
    can chmod the directory holding it.
    """
    def cannot_list(error):
        sink.append(Path(getattr(error, "filename", None) or root))
    return cannot_list


def _exists_but_cannot_be_listed(base: Path) -> bool:
    """A base that is not there is not a hole; one that is there and will not open is.

    `Path.glob` reports the second as the first — it returns no matches rather than raising — so a
    single `chmod` on a base takes every application under it out of the surface silently.
    """
    try:
        with os.scandir(base) as entries:
            next(entries, None)
    except FileNotFoundError:
        return False
    except NotADirectoryError:
        return False
    except OSError:
        return True
    return False


def app_bundle_js_roots(unlistable: list[Path] | None = None) -> list[tuple[Path, int | None]]:
    """(tree, depth bound) for every installed application's own JavaScript, deduplicated by
    filesystem identity — `/Applications/Applications` is a symlink to `/Applications` on macOS,
    which yields each bundle twice, and `Contents/Resources` matches `Contents/resources` on a
    case-insensitive volume. A bundle tree is read whole; a data directory is read to a depth."""
    unlistable = [] if unlistable is None else unlistable
    patterns = [f"{depth}{leaf}" for depth in _BUNDLE_WILDCARD_DEPTHS for leaf in _BUNDLE_LEAVES]
    candidates: list[tuple[Path, list[str], int | None]] = [
        (base, patterns, None) for base in _bundle_bases()]
    candidates += [(base, list(globs), None) for base, globs in _packaged_bases()]
    candidates += [(base, ["*"], _MAX_DATA_DIRECTORY_DEPTH) for base in _data_bases()]
    roots: list[tuple[Path, int | None]] = []
    seen: set = set()
    for base, globs, depth in candidates:
        if _exists_but_cannot_be_listed(base):
            unlistable.append(base)
            continue
        for pattern in globs:
            try:
                matches = sorted(base.glob(pattern))
            except OSError:
                unlistable.append(base)
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


READ = "read"
TOO_FAR_BACK = "too-far-back"
UNREADABLE = "unreadable"


def _tail_lines(path: Path) -> tuple[list[bytes], str]:
    """(the file's last `_TRAILING_LINES_MAX` lines, what happened while reading them).

    Three answers: an unreadable file used to give the same one as a file read and found empty, so
    it reached no finding, no count and no mention. `open()` on a FIFO blocks with no timeout, so
    anything able to append to a module can stop the audit with one named `*.js` beside it.
    """
    wanted = _TRAILING_LINES_MAX
    try:
        regular = stat.S_ISREG(os.stat(path).st_mode)
    except FileNotFoundError:
        # A dangling link, or a file that went between the walk and this — nothing behind it to
        # read, which is the rule `verify.py` states for the same case. Electron cache trees churn
        # `.js` while an audit runs, and grading that as a hole would raise the gate on the churn.
        return [], READ
    except OSError:
        return [], UNREADABLE
    if not regular:
        return [], UNREADABLE
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            if position < _PAD_MIN + _BODY_MIN:
                return [], READ
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
                    return [], TOO_FAR_BACK
            tail = b"".join(reversed(parts))
    except OSError:
        return [], UNREADABLE
    return tail.rstrip(b"\r\n").split(b"\n")[-wanted:], READ


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


@dataclass(frozen=True)
class _MarkerScan:
    """What a content scan of one module's directory established — including whether it happened.

    An empty marker list used to mean all three of nobody asked, ran clean, and could not run —
    the collapse `outcome.py` exists to prevent, one level further down.
    """

    markers: tuple[str, ...] = ()
    stopped_by: str | None = None
    asked: bool = False

    @property
    def blocked(self) -> bool:
        return self.stopped_by is not None

    @property
    def ran(self) -> bool:
        return self.asked and not self.blocked


_NOT_ASKED = _MarkerScan()


def _scan_markers(directory: Path) -> _MarkerScan:
    """CONFIRMED markers in one module's own directory. The engine import is LOCAL, and the scan is
    opt-in because it is slow — see `saw#218` for the measurement.

    `KeyboardInterrupt` is not caught, as in `run_probe`: this runs once per module, so swallowing
    it costs one interrupt per file to stop an audit.
    """
    try:
        from stayawake.bots.security.verify import verify_dir
        return _from_verdict(verify_dir(directory))
    except Exception as exc:
        return _MarkerScan(stopped_by=f"{type(exc).__name__}: {exc}", asked=True)


def _from_verdict(verdict) -> _MarkerScan:
    """The scan's own account of itself, not just its marker list.

    `verify_dir` almost never raises — it reports a tree it could not fully read in the verdict,
    and `scanned_clean` is the only field meaning it looked and found nothing. Two of the others
    return before the scanner runs at all. The sibling in `host_artifacts` reads them all.
    """
    if verdict.markers:
        return _MarkerScan(markers=tuple(verdict.markers), asked=True)
    if verdict.scanned_clean:
        return _MarkerScan(asked=True)
    return _MarkerScan(stopped_by=_why_not_cleared(verdict), asked=True)


def _why_not_cleared(verdict) -> str:
    if verdict.too_large:
        return "it is too large to scan automatically"
    if verdict.partial and verdict.unread:
        # One of the two states behind this returns before the scanner runs at all.
        return "it was not fully scanned (" + "; ".join(verdict.unread) + ")"
    if verdict.partial:
        return "part of it could not be read"
    if verdict.error:
        return f"it could not be fully scanned ({verdict.error})"
    return "the scan did not report a result"


def check_app_bundles(verify: bool = False) -> list[HygieneIssue]:
    """Grade the JavaScript an installed application loads at startup.

    The shape alone is `info`: a build emits neither the pad nor a file that ends right after one,
    but a user-patched bundle is a real thing. `verify=True` (`saw audit --verify`) content-scans
    the module's own directory, and CONFIRMED markers corroborate it into an active foothold — two
    findings rather than one with a hedge, so the rotation gate follows evidence, not shape.

    A scan that could not run is the same two-findings shape: something found and a look that did
    not happen are different claims, and the report groups them differently."""
    issues: list[HygieneIssue] = []
    unbounded = truncated = 0
    unreadable: list[Path] = []
    unreachable: list[Path] = []
    unscanned: list[str] = []
    walked: set = set()
    for root, max_depth in app_bundle_js_roots(unreachable):
        examined = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=True,
                                                    onerror=_note_unreadable(unreachable, root)):
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
                lines, how = _tail_lines(module)
                if how == UNREADABLE:
                    unreadable.append(module)
                    continue
                if how == TOO_FAR_BACK:
                    unbounded += 1
                    continue
                shape = _appended_line(lines) if lines else None
                if shape is None:
                    continue
                scan = _scan_markers(module.parent) if verify else _NOT_ASKED
                if scan.blocked and scan.stopped_by not in unscanned:
                    unscanned.append(scan.stopped_by)
                issues.append(_finding(module, *shape, scan))
            if examined >= _MAX_FILES_PER_ROOT:
                # The cap can also be reached by the LAST module in a directory, where the inner
                # break never runs — measured, one truncation in five on a real application tree.
                truncated = truncated or 1
                break                      # this tree only — the next application still gets read
    notes = [_unexamined_note(unbounded, truncated),
             _unreadable_note(unreadable + unreachable), _unscanned_note(unscanned)]
    return issues + [n for n in notes if n]


def _depth(root: Path, directory: Path) -> int:
    try:
        return len(directory.relative_to(root).parts)
    except ValueError:
        return 0


def _unexamined_note(unbounded: int, truncated: int) -> HygieneIssue | None:
    """What the walk did NOT read. A bound that is not reported reads as coverage of what it cut."""
    parts: list[str] = []
    if truncated:
        parts.append(f"{truncated} tree(s) hold more modules than one audit reads")
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


def _unreadable_note(locations: list[Path]) -> HygieneIssue | None:
    """What the host would not let this read, named.

    Its own grade: the note above counts bounds THIS TOOL chose, and a location the host refused is
    a hole. MEASURED before gating rotation on it — 22477 modules under 44 roots on an ordinary
    host, none unreadable and none anything but a regular file.

    It NAMES them, as the sibling unknown-tier finding does. A count alone raises a gate the
    operator has no way to clear, which is an alarm-fatigue primitive against a gate whose whole
    purpose is to be believed.
    """
    if not locations:
        return None
    return HygieneIssue(
        id=APP_BUNDLE_MODULE_UNREADABLE_ID,
        severity="unknown",
        title="Part of an application could not be read",
        detail="These could not be read, so nothing about what they hold was established, and they "
               "are UNKNOWN rather than clean: " + _named(locations) + ".",
        remediation="Read them yourself, or reinstall the applications they belong to. Do not "
                    f"rotate credentials yet: {_WIPER_NOTE}.",
    )


def _named(locations: list[Path], most: int = 10) -> str:
    shown = "; ".join(str(p) for p in locations[:most])
    beyond = len(locations) - most
    return f"{shown}; and {beyond} more" if beyond > 0 else shown


def _unscanned_note(reasons: list[str]) -> HygieneIssue | None:
    """The corroboration `--verify` promised and did not deliver.

    One item for the run: the modules are named above and the cause is shared. It carries the
    rotation gate, because a scan that did not run cannot say there is no live foothold.
    """
    if not reasons:
        return None
    return HygieneIssue(
        id=APP_BUNDLE_SCAN_BLOCKED_ID,
        severity="unknown",
        title="A module that looks modified was not cleared",
        detail="`--verify` was asked for and the scan did not clear these modules: "
               + "; ".join(reasons) + ". They are UNKNOWN, not clean.",
        remediation="Resolve what stopped it and re-run, or compare each module against the "
                    "vendor's copy. Do not rotate credentials yet: "
                    f"{_WIPER_NOTE}.",
    )


def _finding(module: Path, pad: int, body: int, scan: _MarkerScan) -> HygieneIssue:
    if scan.markers:
        return HygieneIssue(
            id="app-bundle-payload",
            severity="warning",
            title="Worm markers inside an installed application's own JavaScript",
            detail=f"{module} looks modified, and a scan of its directory is CONFIRMED: "
                   f"{', '.join(scan.markers)}.",
            remediation="Treat as a LIVE compromise: isolate the host, reinstall the application, "
                        f"rotate credentials LAST — {_WIPER_NOTE}.",
        )
    return HygieneIssue(
        id="app-bundle-appended-module",
        severity="info",
        title="An application module looks modified",
        detail=f"{module} carries content its build would not have produced. {_corroboration(scan)}",
        remediation="Compare it against the vendor's published copy, or reinstall the application. "
                    "If it is not theirs, isolate this host.",
    )


def _corroboration(scan: _MarkerScan) -> str:
    """What the content scan contributed, said accurately.

    Keep each branch to one short sentence by hand: the word-budget test reads literals out of the
    `HygieneIssue(...)` call, so it cannot see these and will not stop them growing.
    """
    if scan.blocked:
        return "The scan that would clear it did not complete."
    if scan.ran:
        # Hedged: the field behind it is CONFIRMED-only, so "clean" is narrower than it reads.
        return "A scan of its directory found no confirmed markers, which does not clear it."
    return "`saw audit --verify` looks harder at it."
