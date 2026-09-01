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

from .models import HygieneIssue, MODULE_UNREADABLE_ID, SCAN_BLOCKED_ID, _WIPER_NOTE

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


READ = "read"
TOO_FAR_BACK = "too-far-back"
UNREADABLE = "unreadable"


def _tail_lines(path: Path) -> tuple[list[bytes], str]:
    """(the file's last `_TRAILING_LINES_MAX` lines, what happened while reading them).

    Three answers, and an unreadable file used to give the same one as a file that was read and
    held nothing: `([], True)`. It then fell through the shape check with no finding, no count and
    no mention anywhere in the report — the tier below the content scan, deciding whether that scan
    happens at all, saying nothing when it could not decide.

    A file that is not a regular file is not read either. `open()` on a FIFO blocks until something
    writes to it, with no timeout, so anything able to append to a bundle module can also stop the
    audit by creating one named `*.js` beside it. The engine guards exactly this before its own
    read; this side did not.
    """
    wanted = _TRAILING_LINES_MAX
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return [], UNREADABLE
    except OSError:
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

    Three states, and an empty marker list used to be all of them: nobody asked, it ran and found
    nothing, and it could not run. That is the collapse `outcome.py` exists to prevent, one level
    further down — the engine import is local and can fail on its own, and every failure was
    answered with the list a clean scan returns.
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

    `KeyboardInterrupt` is deliberately not caught, as in `run_probe`: this runs once per module,
    so swallowing it here costs one interrupt per file to stop an audit, and the run that carried
    on would report scans nobody performed.
    """
    try:
        from stayawake.bots.security.verify import verify_dir
        return _from_verdict(verify_dir(directory))
    except Exception as exc:
        return _MarkerScan(stopped_by=f"{type(exc).__name__}: {exc}", asked=True)


def _from_verdict(verdict) -> _MarkerScan:
    """The scan's own account of itself, not just its marker list.

    `verify_dir` almost never raises — it reports a tree it could not fully read in the verdict,
    and its docstring says the caller must NOT render that as clean. Reading `.markers` alone made
    every one of those "scanned, found nothing", including the two that return before the scanner
    runs at all: a directory too large to scan, and one holding a pipe or device the scan must not
    open. `scanned_clean` is the only field that means it looked and there was nothing.

    The sibling consumer in `host_artifacts` reads all of these already; this asks the same
    questions rather than a narrower one.
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
        # Not "not everything was read": one of the two states behind this returns before the
        # scanner runs at all, so asserting a partial scan would overstate what happened.
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

    A scan that could not run is the same two-findings shape: the module keeps its `info` grade for
    what was observed, and the hole is its own item — something found and a look that did not
    happen are different claims, and the report groups them differently."""
    issues: list[HygieneIssue] = []
    unbounded = truncated = unreadable = 0
    unscanned: list[str] = []
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
                lines, how = _tail_lines(module)
                if how == UNREADABLE:
                    unreadable += 1
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
                break                      # this tree only — the next application still gets read
    notes = [_unexamined_note(unbounded, truncated), _unreadable_note(unreadable),
             _unscanned_note(unscanned)]
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


def _unreadable_note(count: int) -> HygieneIssue | None:
    """Modules the host would not let this read at all.

    Its own grade, not folded into the note above: the two counted there are bounds THIS TOOL
    chose, and a location the host refused is a hole, which is the one that withholds the rotation
    all-clear. MEASURED before gating it — 22477 modules under 44 enumerated roots on an ordinary
    macOS host, none of them unreadable and none of them anything but a regular file.
    """
    if not count:
        return None
    return HygieneIssue(
        id=MODULE_UNREADABLE_ID,
        severity="unknown",
        title="An application module could not be read",
        detail=f"{count} module(s) an installed application loads could not be read at all, so "
               "nothing about them was established. They are UNKNOWN, not clean.",
        remediation="Read them yourself, or reinstall the applications. Do not rotate credentials "
                    f"yet: {_WIPER_NOTE}.",
    )


def _unscanned_note(reasons: list[str]) -> HygieneIssue | None:
    """The corroboration `--verify` promised and did not deliver.

    One item for the run rather than one per module: the modules are already named above, and the
    cause is the same for all of them. It carries the rotation gate, because a scan that did not
    run cannot say there is no live foothold — and rotating over one is the reported wiper trigger.
    """
    if not reasons:
        return None
    return HygieneIssue(
        id=SCAN_BLOCKED_ID,
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

    One sentence used to cover all three states, and it read "`saw audit --verify` looks harder at
    it" — which is advice to run what the operator had just run, over a scan that failed, and a
    result withheld from one that succeeded.

    Keep each branch to one short sentence by hand: the word-budget test reads string literals out
    of the `HygieneIssue(...)` call, so it cannot see these and will not stop them growing.
    """
    if scan.blocked:
        return "The scan that would clear it did not complete."
    if scan.ran:
        # Hedged, because the field behind it is CONFIRMED-only: the engine drops its weaker tiers
        # before answering, so "clean" here is narrower than an operator reads it. The sibling
        # consumer attaches the same caution to the same field, and the first version of this
        # dropped it.
        return "A scan of its directory found no confirmed markers, which does not clear it."
    return "`saw audit --verify` looks harder at it."
