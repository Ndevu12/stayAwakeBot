#!/usr/bin/env python3
"""Symlink matcher.

Reports two anomalies from a symlink's own metadata — one confirmed, one heuristic — without ever
following the link or reading what is behind it.
"""
from __future__ import annotations

import os
from pathlib import Path

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.write_sinks import (CONTROL_EXEC_LABEL, control_exec_sink, sink_label)
from stayawake.lib.git.query import exec_paths

_MAX_LINK_HOPS = 40
_MAX_LINK_STATES = 256


def _finding(sig: dict, rel: str, evidence: str) -> Finding:
    return Finding(
        signature_id=sig["id"], category=sig["category"], severity=Severity.parse(sig["severity"]),
        path=rel, description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=evidence, vector=sig["category"], composed_evidence=True)


def _classify(p: Path, repo_root: Path, resolved_root: Path,
              redirect_sig: dict | None, escape_sig: dict | None, is_dir: bool,
              runs_from: set | None = None) -> Finding | None:
    """Grade a symlink on disk. Takes the link, the repository root, its resolved form, the two
    signatures and whether it names a directory. Returns the finding it warrants, or None — a link
    whose target cannot be resolved is not graded."""
    try:
        if not p.is_symlink():
            return None
    except OSError:
        return None
    try:
        resolved = p.resolve()
    except (OSError, RuntimeError):
        return None                           # ELOOP / unresolvable → skip
    try:
        raw = os.readlink(p)
    except OSError:
        raw = "?"
    try:
        rel = str(p.relative_to(repo_root))
    except ValueError:
        rel = str(p)
    return _graded(rel, raw, resolved, resolved_root, redirect_sig, escape_sig, is_dir,
                   runs_from)


def _graded(rel: str, raw: str, resolved: Path, resolved_root: Path,
            redirect_sig: dict | None, escape_sig: dict | None, is_dir: bool,
            runs_from: set | None = None) -> Finding | None:
    """Grade a link at `rel` naming `raw`. Takes the path it is known by, the target it names, where
    that target resolves to, the repository root, the two signatures and whether it names a
    directory. Returns the finding it warrants, or None."""
    if redirect_sig is not None and control_exec_sink(resolved, runs_from):
        return _finding(redirect_sig, rel,
                        f"symlink → {raw} redirects a write into {CONTROL_EXEC_LABEL}")
    if resolved == resolved_root or resolved_root in resolved.parents:
        return None
    if redirect_sig is not None:
        label = sink_label(raw, resolved)
        if label is not None:                 # escaping → a sensitive write-sink → CONFIRMED critical
            return _finding(redirect_sig, rel, f"symlink → {raw} redirects a write into {label}")
    if escape_sig is not None and is_dir:      # escaping directory → non-sink → scan-evasion HEURISTIC
        return _finding(escape_sig, rel, f"symlink → {raw} resolves outside the repo root (contents unscanned)")
    return None


def _parts(target: str) -> list:
    """Split a link target into the components a checkout walks. Takes the target. Returns them."""
    return [part for part in target.split("/") if part and part != "."]


def _landings(rel: str, raw: str, stored: dict, budget: int = _MAX_LINK_STATES) -> set:
    """Follow a stored target the way a checkout walks one, through the links the repository also
    stores. Takes the path it is stored at, the target it names, every stored link and a bound on
    the work. Returns each `(path, left the repository)` pair it can land on, anchored at the root."""
    seen, out = set(), set()
    states = [(([] if raw.startswith("/") else _parts(os.path.dirname(rel))),
               _parts(raw), raw.startswith("/"), _MAX_LINK_HOPS)]
    while states:
        if budget <= 0:
            out.add((os.path.normpath(os.path.join(os.sep, os.path.dirname(rel), raw)), True))
            break
        budget -= 1
        walked, pending, left, hops = states.pop()
        while pending:
            part, pending = pending[0], pending[1:]
            if part == os.pardir:
                if walked:
                    walked = walked[:-1]
                else:
                    left = True
                continue
            walked = walked + [part]
            here = "/".join(walked)
            if left or here not in stored or hops <= 0 or (here, hops) in seen:
                continue
            seen.add((here, hops))
            for target in stored[here]:
                states.append((([] if target.startswith("/") else walked[:-1]),
                                _parts(target) + pending,
                                left or target.startswith("/"), hops - 1))
            walked, pending = None, None
            break
        if walked is not None:
            out.add(("/" + "/".join(walked), left))
    return out


def _stored_finding(rel: str, raw: str, stored: dict, redirect_sig: dict | None) -> list:
    """Grade a stored version at `rel` naming `raw`. Takes the path it is stored at, the target it
    names, every stored link and the redirect signature. Returns the findings it warrants."""
    if redirect_sig is None:
        return []
    reaches_exec = False
    for land, left in sorted(_landings(rel, raw, stored)):
        if left:
            label = sink_label(raw, Path(land))
            if label is not None:
                return [_finding(redirect_sig, rel,
                                 f"symlink → {raw} redirects a write into {label}")]
        reaches_exec = reaches_exec or control_exec_sink(Path(land))
    if reaches_exec:
        return [_finding(redirect_sig, rel,
                         f"symlink → {raw} redirects a write into {CONTROL_EXEC_LABEL}")]
    return []


class SymlinkMatcher(Matcher):
    handles = "symlink"

    def scan(self, target, signatures):
        by_id = {s["id"]: s for s in signatures}
        redirect_sig = by_id.get("symlink-write-redirect")
        escape_sig = by_id.get("symlink-escapes-repo")
        if redirect_sig is None and escape_sig is None:
            return []
        try:
            root = target.root.resolve()
        except (OSError, RuntimeError):
            return []
        exclude = getattr(target.opts, "exclude_dirs", set())
        runs_from = exec_paths(target.root)
        findings: list[Finding] = []
        if getattr(target, "names_one_file", False):
            for rel in (target.include_only or ()):
                entry = target.root / rel
                esc = None if entry.name in exclude else escape_sig
                f = _classify(entry, target.root, root, redirect_sig, esc, entry.is_dir(),
                              runs_from)
                if f is not None:
                    findings.append(f)
            return findings
        stored = getattr(target, "stored_links", None)
        if stored is not None:
            for rel, raws in sorted(stored.items()):
                for raw in raws:
                    findings += _stored_finding(rel, raw, stored, redirect_sig)
            return findings
        for dirpath, dirnames, filenames in os.walk(target.scan_root):  # followlinks=False (default)
            for name in dirnames:
                esc = None if name in exclude else escape_sig
                f = _classify(Path(dirpath) / name, target.root, root, redirect_sig, esc, True,
                              runs_from)
                if f is not None:
                    findings.append(f)
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for name in filenames:
                f = _classify(Path(dirpath) / name, target.root, root, redirect_sig, escape_sig,
                              False, runs_from)
                if f is not None:
                    findings.append(f)
        return findings
