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
            self.read_errors.append(f"{rel}: {type(exc).__name__}")
            return None

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
            self.read_errors.append(f"{p.name}: {type(exc).__name__}")   # unreadable oversized file — a gap
            return b""

    def read_text(self, rel: str) -> str | None:
        p = self.root / rel
        ext = _ext(rel)
        try:
            size = p.stat().st_size
        except FileNotFoundError:
            return None                           # vanished (race) — benign skip
        except OSError as exc:
            self.read_errors.append(f"{rel}: {type(exc).__name__}")      # present but unstattable — a gap
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

    def cleanup(self) -> None:
        pass

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()
