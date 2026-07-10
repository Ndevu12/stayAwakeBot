#!/usr/bin/env python3
"""Target base + scan options.

A Target is a directory tree the matchers read from. Subclasses differ only in
how the tree gets there (already on disk vs cloned). Same interface ⇒ the scanner
is decoupled from the source (DIP).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# Source/text extensions we always attempt to scan even when a file looks "binary"
# (NUL bytes) or exceeds the size cap — the worm hides in exactly these, so one NUL
# byte or 2 MB of padding must not buy it invisibility.
SOURCE_EXTS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
    ".json", ".vue", ".svelte", ".md", ".yml", ".yaml", ".sh", ".bash",
    ".py", ".rb", ".php", ".go", ".rs", ".html", ".htm", ".css", ".map",
}


# Consecutive interior windows (read_source_windows) overlap by this many bytes so a match spanning a
# window boundary is still seen whole in one window. The guarantee is EXACT for any match up to
# _SOURCE_WINDOW_OVERLAP bytes long; every shipped content signature is line-local and matches far less
# than this (< ~1 KB even with whitespace tolerance), so in practice no real payload straddles. A match
# LONGER than the overlap is only constructible with a pathological multi-KB run of whitespace/hex
# inside the pattern — a documented residual, not a realistic evasion. 64 KiB costs ~3% re-read on a
# 2 MB window.
_SOURCE_WINDOW_OVERLAP = 65_536

# Full-interior windowing is bounded to files up to this size; a larger file falls back to the head+tail
# read (as any oversized file does), so a hostile target cannot force unbounded scan work with a single
# enormous file. 64 MB comfortably covers every realistic source file (the largest real minified bundles
# are ~25 MB); the deep middle of a file larger than this is a documented residual.
_MAX_INTERIOR_SCAN_BYTES = 64_000_000


def _ext(rel: str) -> str:
    i = rel.rfind(".")
    return rel[i:].lower() if i != -1 else ""


@dataclass
class ScanOptions:
    # Two kinds of exclusion, both deliberate (see docs/SECURITY_ARCHITECTURE.md → "Provenance is
    # not trust"):
    #  * BUILD OUTPUTS — "node_modules", ".next", "dist", "build": compiled/vendored artifacts where
    #    minification IS obfuscation, so the density heuristic there would be all false positives.
    #    This is a build-artifact trust decision, NOT a provenance one — `saw` never trusts an
    #    attestation; it just doesn't judge post-build shape. A payload minified into a bundle is a
    #    documented residual (obfuscation.py docstring), and settings can override this set to include
    #    them. Known loader FINGERPRINTS still match anywhere that IS traversed.
    #  * SELF-OUTPUT — ".malware-quarantine": the scanner's own quarantine holds removed payload
    #    lines verbatim, so scanning it self-triggers. ("reports"/"sab-patches" are NO LONGER
    #    excluded (#1143): the health sentinel commits no reports (its status is one GitHub issue),
    #    and a security report/patch stores REDACTED evidence (sha256 + short preview), not the raw
    #    IoC — so they don't self-trigger. Excluding those common dir names globally was just a
    #    hiding spot when scanning a target repo.)
    exclude_dirs: set[str] = field(default_factory=lambda: {
        ".git", "node_modules", ".next", "dist", "build", ".malware-quarantine"})
    max_file_bytes: int = 2_000_000
    remote_clone_depth: int = 50
    # Opt-in (config `scan_build_outputs: true`): also scan build outputs. When set, the service
    # un-prunes the build-output dirs above AND the obfuscation matcher runs its self-evident
    # construct checks (numeric array / exec sink / base64 / escape run) on generated paths — but
    # NOT the whole-file density heuristic (density is genuinely expected in bundles) — emitting a
    # `heuristic` `obfuscated-build-artifact` finding, never `confirmed`. Default off (FP-safe
    # defaults unchanged).
    scan_build_outputs: bool = False
    # ON by default — offline, deterministic and free (the corpus is already loaded for malware):
    # surface ordinary dependency CVEs (the `vulnerable-dependency` tier) alongside malware, in their
    # own section, NEVER moving the worm verdict (see ScanResult.advisories). Only produces output
    # when a `saw db update` cache exists. `saw scan --no-advisories` (or config
    # `dependency_advisories: false`) suppresses the section.
    dependency_advisories: bool = True
    # OPT-IN, off by default (`saw scan --external` / config `external_audit: true`): additionally run
    # INSTALLED external auditors (osv-scanner, …). This is the ONE thing that crosses the offline
    # guarantee — it spawns subprocesses and a tool may send the dependency graph to its own servers —
    # so it must be requested explicitly. Also never moves the worm verdict.
    external_audit: bool = False


class Target:
    source = "local"

    def __init__(self, root: str | Path, display: str, opts: ScanOptions):
        self.root = Path(root)
        self.display = display
        self.opts = opts
        # Files that EXIST (os.walk yielded them) but could not be READ — a permission error, a
        # restrictive ACL, etc. These are scan GAPS, not benign skips: scan_target promotes them to
        # result.error so the run fails CLOSED. A payload behind an unreadable file must never be
        # silently skipped and read as clean.
        self.read_errors: list[str] = []

    @property
    def repo_root(self) -> Path:
        return self.root

    def iter_files(self) -> Iterator[str]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in self.opts.exclude_dirs]
            for fn in filenames:
                yield str((Path(dirpath) / fn).relative_to(self.root))

    def _note_unreadable(self, name: str, p: Path, exc: OSError) -> None:
        """A file present but unreadable is a scan GAP → recorded so the run fails CLOSED — EXCEPT a
        SYMLINK, whose read failure is a loop (ELOOP), an escape, or a broken/dangling target: a benign
        skip, not scannable content (an escaping link is surfaced separately by the symlink matcher).
        Recording a symlink cycle as an 'unreadable file' would wrongly fail the whole scan (#1146)."""
        try:
            if p.is_symlink():
                return                            # symlink loop/escape/broken → benign skip
        except OSError:
            pass                                  # can't tell (e.g. EACCES on 3.11) → be conservative
        self.read_errors.append(f"{name}: {type(exc).__name__}")   # genuine gap → fail CLOSED

    def read_bytes(self, rel: str, limit: int | None = None) -> bytes | None:
        p = self.root / rel
        try:
            if limit is None and p.stat().st_size > self.opts.max_file_bytes:
                return None                       # policy skip (too large) — a benign skip
        except OSError:
            return None                           # can't stat (vanished / race) — treat as absent
        try:
            with p.open("rb") as fh:
                return fh.read(limit) if limit else fh.read()
        except OSError as exc:
            # Present but unreadable — a scan GAP, not a benign skip. Record it (fail closed).
            self._note_unreadable(rel, p, exc)
            return None

    def _nonsource_scan_text(self, rel: str, p: Path, size: int) -> str | None:
        """A NUL-stripped, bounded head+tail of a NON-source file for the confirmed content tier only.
        A payload under a non-source extension (an oversized `.bin`, a NUL-laden fake `.png`) is skipped
        by ``read_text``; this lets the cheap line-local content regexes still see a bounded window of
        it. Head+tail (not head-only) so an appended payload is covered too, matching the oversized
        source read. NUL bytes are stripped so 'binary' bytes decode to scannable text."""
        if size > self.opts.max_file_bytes:
            raw = self._head_tail(p, max(1, self.opts.max_file_bytes // 2))
        else:
            raw = self.read_bytes(rel)
        if not raw:
            return None
        return raw.replace(b"\x00", b"").decode("utf-8", errors="replace")

    def _head_tail(self, p: Path, half: int) -> bytes:
        """Read a bounded head+tail of an oversized file (payload is usually
        appended, so the tail matters) instead of skipping it wholesale."""
        try:
            with p.open("rb") as fh:
                head = fh.read(half)
                try:
                    fh.seek(-half, os.SEEK_END)
                except OSError:
                    fh.seek(0)
                tail = fh.read(half)
            return head + b"\n/*\xe2\x80\xa6stayawake-truncated\xe2\x80\xa6*/\n" + tail
        except OSError as exc:
            self._note_unreadable(p.name, p, exc)   # unreadable oversized file — a gap (unless a symlink)
            return b""

    def read_text(self, rel: str) -> str | None:
        p = self.root / rel
        ext = _ext(rel)
        try:
            size = p.stat().st_size
        except FileNotFoundError:
            return None                           # vanished (race) — benign skip
        except OSError as exc:
            self._note_unreadable(rel, p, exc)    # present but unstattable — a gap (unless a symlink)
            return None
        if size > self.opts.max_file_bytes:
            if ext not in SOURCE_EXTS:
                return None                       # genuinely large binary — skip
            raw = self._head_tail(p, max(1, self.opts.max_file_bytes // 2))
        else:
            raw = self.read_bytes(rel)
            if raw is None:
                return None
        if b"\x00" in raw[:8192]:
            if ext in SOURCE_EXTS:
                raw = raw.replace(b"\x00", b"")   # NUL-laden source is itself suspicious — scan anyway
            else:
                return None                       # real binary asset
        return raw.decode("utf-8", errors="replace")

    def read_source_windows(self, rel: str) -> Iterator[tuple[int, str]]:
        """Yield ``(line_offset, text)`` chunks covering the WHOLE body of a source file.

        ``read_text`` truncates an oversized source file to head+tail, so the interior (offset
        ~1 MB .. size-1 MB) is unscanned — a payload buried there is invisible to every matcher
        (#1145, blind spot #5 of #1141). This reader streams the full file in overlapping windows
        so no interior region is skipped. It is for the CHEAP, line-local confirmed content-regex
        tier ONLY (ContentMatcher). The expensive whole-file density heuristic deliberately stays
        head/tail-bounded via ``read_text`` — do NOT route it through here (it is FP-prone on the
        large minified bundles this method now reads in full).

        Memory stays bounded: at most one window is resident (``max_file_bytes`` bytes), regardless
        of file size — a 500 MB source file is scanned in ~2 MB working-set chunks, never read whole.
        Total work is bounded too: files larger than ``_MAX_INTERIOR_SCAN_BYTES`` fall back to the
        head+tail read so a hostile target can't force unbounded scanning with one enormous file.
        ``line_offset`` is the count of newlines BEFORE the window's first byte, computed in the byte
        domain (a caller adds ``text.count("\\n", 0, match)`` to it for the absolute 1-based line).
        Small files (<= cap) yield exactly one ``(0, text)`` window equal to ``read_text`` — the
        common path is byte-for-byte unchanged (verdict-identical).
        """
        p = self.root / rel
        ext = _ext(rel)
        try:
            size = p.stat().st_size
        except FileNotFoundError:
            return                                # vanished (race) — benign skip
        except OSError as exc:
            self._note_unreadable(rel, p, exc)    # unstattable — a gap (unless a symlink loop/escape)
            return
        if ext not in SOURCE_EXTS:
            # NON-source file: the confirmed content tier (this reader's ONLY consumer) scans a bounded,
            # NUL-stripped head+tail so a payload hidden under a benign extension — an oversized `.bin`,
            # a NUL-laden `.png` — isn't invisible (#6/#7 of #1141). read_text skips these, so ONLY the
            # cheap FP-safe content-loader regexes see this text; the density/whitespace heuristics are
            # extension-gated to source and never run here (measured: the confirmed tier ~0 FP on real
            # binaries, the density tier 12-33% — so scanning binary heads adds catch, not false results).
            text = self._nonsource_scan_text(rel, p, size)
            if text is not None:
                yield (0, text)
            return
        if size <= self.opts.max_file_bytes:
            text = self.read_text(rel)            # reuse the exact small-file semantics (NUL/decode)
            if text is not None:
                yield (0, text)
            return
        if size > _MAX_INTERIOR_SCAN_BYTES:
            # Too large to window in full without becoming a DoS surface — fall back to the head+tail
            # read (preserves appended-payload/tail coverage); the deep middle is a documented residual.
            text = self.read_text(rel)
            if text is not None:
                yield (0, text)
            return
        window = self.opts.max_file_bytes
        # Clamp the step so a tiny cap (overlap >= window, e.g. tests) can't yield a non-positive
        # step and loop forever.
        step = max(1, window - min(_SOURCE_WINDOW_OVERLAP, window // 2))
        nl_before = 0
        pos = 0
        try:
            with p.open("rb") as fh:
                while pos < size:
                    fh.seek(pos)
                    raw = fh.read(window)
                    if not raw:
                        break
                    chunk = raw.replace(b"\x00", b"")   # NUL-laden source is scanned anyway (as read_text)
                    yield (nl_before, chunk.decode("utf-8", errors="replace"))
                    nl_before += raw.count(b"\n", 0, step)   # newlines we step past (byte domain — exact)
                    pos += step
        except OSError as exc:
            self._note_unreadable(rel, p, exc)    # unreadable oversized file — a gap (unless a symlink)
            return

    def cleanup(self) -> None:
        pass

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()
