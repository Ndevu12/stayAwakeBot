#!/usr/bin/env python3
"""Content-verify a single SUSPECT directory by scanning it with the worm signatures.

`saw audit`'s host-artifact probe can flag a *weak* indicator — a `~/.node_modules` sitting in
`$HOME` — that a manual `npm install` produces just as readily as the worm. This turns that weak
indicator into an actual verdict by looking INSIDE the directory: it scans the tree with the normal
signatures but with the everyday `exclude_dirs` turned OFF (we deliberately WANT to look inside
`node_modules`/`dist`/`build` here — the exact opposite of a repository scan).

Deliberately decoupled from `saw scan`: this calls the engine (`scan_target`) directly on one chosen
directory and NEVER goes through repository discovery (`discover_local_repos`), so `saw scan`'s
"find and scan every git repo" behaviour is completely untouched. The two only share the engine. It is:
  * opt-in       — reached from a `saw audit` flag, never run by default;
  * bounded       — a huge, almost-certainly-legitimate `node_modules` bails rather than hang;
  * confirmed-only — a tree of minified libraries must NOT be mistaken for malware on heuristic
                     density alone, so only CONFIRMED signature hits count as markers;
  * fail-honest   — a read gap or an over-size tree is reported as such, never as "clean".
"""
from __future__ import annotations

import os
import stat as _stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
# The scanner's OWN full-read thresholds — imported so our coverage check can't drift from what the
# confirmed content tier actually reads (a non-source file over max_file_bytes, or a source file over
# _MAX_INTERIOR_SCAN_BYTES, is only head+tail-scanned, so its middle is unseen).
from stayawake.bots.security.targets.base import SOURCE_EXTS, _MAX_INTERIOR_SCAN_BYTES

# A worm's staged `~/.node_modules` drop is SMALL (a package.json + a couple of deps); a real
# project's node_modules is huge. So a moderate cap fully scans the suspicious case and bails on a
# big, almost certainly legitimate tree — where "too large" is itself a mild reassurance, not a
# false "clean". Opt-in, so the caller may raise it when the user asks for a deeper look.
DEFAULT_MAX_FILES = 4000

# Excludes OFF except `.git` — the whole point is to look inside node_modules/dist/build (the dirs a
# normal repo scan skips). `.git` internals are never worm-drop targets and only slow the walk.
_VERIFY_EXCLUDES = {".git"}


@dataclass
class DirVerdict:
    """The outcome of content-verifying one suspect directory. `markers` holds CONFIRMED signature
    ids (heuristic-only hits are deliberately excluded — see the module docstring).

    `scanned_clean` is the ONLY reassuring state and is set ONLY when the whole tree was both walked
    AND fully read. The caller reads the states in priority order: markers → clean → too_large →
    partial → error. Anything but markers/clean means "we did not fully verify" — never rendered as
    clean (the #1220 rule: don't claim clean when you didn't look)."""
    path: str
    files: int = 0
    markers: list[str] = field(default_factory=list)
    scanned_clean: bool = False   # fully walked AND fully read, no confirmed markers
    too_large: bool = False       # bailed BEFORE scanning — larger than max_files
    partial: bool = False         # walked, but not fully READ (an oversize file, or an escaping
                                  # directory symlink whose contents os.walk never descends)
    error: str | None = None      # not-a-dir, or a read gap that means we CANNOT claim "clean"

    @property
    def has_markers(self) -> bool:
        return bool(self.markers)


def _escapes_root(p: Path, root_resolved: Path) -> bool:
    """True when `p` is a DIRECTORY symlink whose target resolves OUTSIDE root. os.walk
    (followlinks=False) never descends it, so its contents are never scanned — a "clean" verdict
    over such a tree would be dishonest. A link staying within root is fine (its target is walked via
    its real path); a file symlink is followed on open and read, so it is not a coverage hole here."""
    try:
        if not p.is_symlink():
            return False
        target = p.resolve()
    except OSError:
        return True                       # can't resolve → be honest, assume unscanned
    try:
        target.relative_to(root_resolved)
        return False
    except ValueError:
        return True


def _coverage(p: Path, max_file_bytes: int) -> str:
    """Classify how the scanner's confirmed content tier covers one file:
      * 'full'    — the scanner reads its whole content;
      * 'partial' — only head+tail (an oversized file), or NOT read at all (a symlink whose target
                    exists but is unreadable — silently benign-skipped by the scan with no gap
                    recorded, so unlike a plain unreadable file it would otherwise read as clean);
      * 'special' — a FIFO/socket/device whose BLOCKING open() could hang the scan forever; the caller
                    must NOT scan such a tree (a dangling symlink is 'full' — no content behind it).
    `stat` FIRST (it follows a symlink to its target), so we classify a FIFO BEFORE ever opening it."""
    try:
        st = p.stat()
    except FileNotFoundError:
        return "full"                     # dangling symlink / vanished → nothing behind it to scan
    except OSError:
        return "partial"                  # ELOOP / unstat-able path → we could not see it
    if not _stat.S_ISREG(st.st_mode):
        return "special"                  # FIFO / socket / device → a blocking open() could hang
    try:
        if p.is_symlink():                # a symlink to a REAL file: confirm the scan can READ it
            with p.open("rb") as fh:      # (a regular-file target won't block on open)
                fh.read(1)
    except OSError:
        return "partial"                  # exists but unreadable → the scan silently skips it
    limit = _MAX_INTERIOR_SCAN_BYTES if p.suffix.lower() in SOURCE_EXTS else max_file_bytes
    return "partial" if st.st_size > limit else "full"


def _survey(root: Path, cap: int, max_file_bytes: int) -> tuple[int | None, bool, bool]:
    """Walk `root` (excluding `.git`, not following symlinks — the SAME walk the scan uses) and
    return `(file_count | None if it exceeds cap, complete, scannable)`:
      * `complete` is False whenever the tree could not be fully READ (unreadable/​unlistable dir,
        escaping directory symlink, oversized file, or unreadable symlinked file) — so a caller must
        NOT report it as clean. (A plain unreadable NON-symlink file is caught separately: the scan
        fails CLOSED via result.error.)
      * `scannable` is False when the tree holds a FIFO/socket/device the blocking scan could HANG on
        — the caller must skip scanning entirely and report an honest 'could not verify'."""
    root_resolved = root.resolve()
    n = 0
    complete = True
    scannable = True

    def _onerror(_exc: OSError) -> None:
        nonlocal complete
        complete = False                  # a dir we couldn't list → its contents went unscanned

    for dirpath, dirnames, filenames in os.walk(root, onerror=_onerror):
        kept = []
        for d in dirnames:
            if d in _VERIFY_EXCLUDES:
                continue
            if _escapes_root(Path(dirpath) / d, root_resolved):
                complete = False
            kept.append(d)
        dirnames[:] = kept
        for fn in filenames:
            n += 1
            if n > cap:
                return None, complete, scannable
            cov = _coverage(Path(dirpath) / fn, max_file_bytes)
            if cov == "special":
                scannable = False
                complete = False
            elif cov == "partial":
                complete = False
    return n, complete, scannable


def verify_dir(path: str | Path, *, max_files: int = DEFAULT_MAX_FILES,
               signatures: dict[str, list[dict[str, Any]]] | None = None) -> DirVerdict:
    """Content-scan one suspect directory and return an honest `DirVerdict`.

    Bounded (bails past `max_files` rather than hang on a huge real node_modules) and graded on
    CONFIRMED signatures only. Never raises for an unreadable/missing path — it degrades to an
    `error` verdict, which the caller must NOT render as "clean". `signatures` may be passed in so a
    caller verifying several dirs loads the DB once."""
    root = Path(path)
    try:
        if not root.is_dir():
            return DirVerdict(path=str(root), error="not a directory")
    except OSError as exc:
        return DirVerdict(path=str(root), error=f"unreadable: {exc}")

    # A fresh, LOCAL ScanOptions — never the defaults `saw scan` uses; excludes off except `.git`.
    opts = ScanOptions(exclude_dirs=set(_VERIFY_EXCLUDES))
    count, complete, scannable = _survey(root, max_files, opts.max_file_bytes)
    if count is None:
        return DirVerdict(path=str(root), too_large=True)
    if not scannable:              # a FIFO/socket/device present — the scan's open() could HANG; skip it
        return DirVerdict(path=str(root), files=count, partial=True)

    sigs = signatures if signatures is not None else load_signatures()
    result = scan_target(LocalRepoTarget(root, str(root), opts), sigs, [])
    markers = sorted({f.signature_id for f in result.findings if f.confidence == CONFIRMED})
    if markers:                    # a CONFIRMED hit wins regardless of coverage
        return DirVerdict(path=str(root), files=count, markers=markers)
    if result.error:               # a read gap → we did NOT fully see the tree; must not claim "clean"
        return DirVerdict(path=str(root), files=count, error=result.error)
    if not complete:               # walked, but an oversize file / escaping symlink went UNREAD
        return DirVerdict(path=str(root), files=count, partial=True)
    return DirVerdict(path=str(root), files=count, scanned_clean=True)
