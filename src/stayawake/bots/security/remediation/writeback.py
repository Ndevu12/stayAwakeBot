#!/usr/bin/env python3
"""Code-loader remediation APPLY — the side-effecting write tail: back up the original to quarantine,
write the recovered/excised text, and re-prove the safety gate before committing to disk (verify-or-
revert). `apply_recovery` (git restore / git-corroborated excision) and `apply_suggested`."""
from __future__ import annotations

import shutil
from pathlib import Path

from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.remediation.changes import _backup
from stayawake.bots.security.remediation.gates import (
    _carries_payload, _ext, _seam_strip, _is_subsequence, _safe_to_recover)
from stayawake.bots.security.remediation.classify import Recovery, Suggested

def _backup_write_verify(root: Path, rel: str, new_text: str, quarantine: Path, content_sig) -> bool:
    """The shared write TAIL of every remediation (git RESTORE, git-corroborated EXCISION, and the
    computed strip): back up the current file to `quarantine`, write `new_text`, then
    verify-or-revert — the written file must read back byte-identical AND carry neither a loader
    literal nor an exec sink (`_carries_payload`), else the original is restored. One home for the
    backup + verify + revert net so it is identical for every write path (never downgraded)."""
    target = root / rel
    try:
        if target.stat().st_nlink > 1:
            return False
    except OSError:
        return False
    _backup(root, rel, quarantine)
    target.write_text(new_text, encoding="utf-8")
    restored = target.read_text(encoding="utf-8", errors="replace")
    if restored != new_text or _carries_payload(restored, content_sig):
        backup = quarantine / rel
        if backup.exists():
            shutil.copy2(backup, target)
        return False
    return True


def _apply_seam_excision(root: Path, rel: str, expected: str, quarantine: Path, content_sig) -> bool:
    """Write a concealment-seam excision, re-proving `expected` against the bytes on disk NOW:
    non-empty, a safe write target (NEVER through a symlink or outside the worktree — the shared
    the quarantine + verify net dead), the file exists, the result carries no payload, and — the
    load-bearing check — re-running the deterministic `_seam_strip` on the CURRENT file reproduces
    `expected` EXACTLY. That single equality re-checks every gate (each seam still validates, the
    shim is still dead, the result carries no payload and is not packed, subsequence) against the
    live bytes; if the file changed since classify, the strip differs and we refuse. Then the
    shared backup → write → verify-or-revert tail.

    Shared by a GIT-CORROBORATED `Recovery(excised=True)` and a COMPUTED `Suggested`: the
    WRITE safety is byte-for-byte identical; they differ ONLY in provenance (whether a clean ancestor
    corroborated `expected`), which the caller reflects in a separate commit / PR section, never in
    the bytes or the proof."""
    target = root / rel
    if not expected or not is_safe_write_target(target, root):
        return False
    if not target.exists() or _carries_payload(expected, content_sig):
        return False
    current = target.read_text(encoding="utf-8", errors="replace")
    if _seam_strip(current, _ext(rel), content_sig) != expected:
        return False                      # the canonical strip no longer reproduces it → refuse
    return _backup_write_verify(root, rel, expected, quarantine, content_sig)


def _apply_whole_file_restore(root: Path, rel: str, expected: str, quarantine: Path, content_sig) -> bool:
    """Write a WHOLE-FILE restore (a clean 3-way-merge version,), re-proving `expected` against
    the bytes on disk NOW with the SAME gates a non-excised `Recovery` uses — NOT `_seam_strip`, which
    is specific to concealment-seam excisions. `expected` must be a safe write target, carry no
    payload, be `current` minus a provably payload-only delta (`_safe_to_recover`) with no fabricated
    byte (`_is_subsequence`), then the shared backup → write → verify-or-revert tail. Identical WRITE
    safety to `apply_recovery`'s restore arm; the ONLY difference is provenance (a synthesized merge
    tree, not committed first-parent history), which is why the caller lands it as a review-required
    computed-tier commit and never auto-trusts it."""
    target = root / rel
    if not expected or not is_safe_write_target(target, root):
        return False
    if not target.exists() or _carries_payload(expected, content_sig):
        return False
    current = target.read_text(encoding="utf-8", errors="replace")
    if not _safe_to_recover(current, expected, content_sig) or not _is_subsequence(expected, current):
        return False                      # not 'current minus payload' → refuse (never revert legit work)
    return _backup_write_verify(root, rel, expected, quarantine, content_sig)


def apply_recovery(repo, rec: Recovery, quarantine: Path, content_sig) -> bool:
    """Write `rec.clean_text` (after backing up the infected file), re-proving safety against the
    bytes on disk NOW — proven independently of the planner, so a stale/mismatched `clean_text`
    can never slip through — and reverting if the write doesn't verify.

    The pre-proof depends on how `clean_text` was derived:
      * a surgical EXCISION (`rec.excised`): delegated to `_apply_seam_excision` — re-run the
        deterministic `_seam_strip` on the CURRENT file; it must reproduce `clean_text` exactly.
      * a git RESTORE (`rec.excised` is False): the delta must be provably payload-only
        (`_safe_to_recover`) AND `clean_text` a subsequence of the file (`_is_subsequence`, no
        fabricated byte).
    AFTER writing (shared tail), the restored file must match byte-for-byte and carry neither a
    loader literal nor an exec sink, else the original is put back."""
    root = Path(repo)
    if rec.excised:
        return _apply_seam_excision(root, rec.path, rec.clean_text, quarantine, content_sig)
    target = root / rec.path
    if not rec.clean_text or not is_safe_write_target(target, root):
        # worktree) and `_backup` skips symlinks, so the quarantine + verify-or-revert net would be
        # dead. The containment check also closes a symlinked ANCESTOR dir or a `..`. Defers to manual.
        return False
    if not target.exists() or _carries_payload(rec.clean_text, content_sig):
        return False                      # never write a version that still carries the payload
    current = target.read_text(encoding="utf-8", errors="replace")
    # No legit byte dropped (delta provably payload-only) and no fabricated byte. Either failing
    # means clean_text is not 'current minus payload' → refuse rather than risk reverting legit work.
    if not _safe_to_recover(current, rec.clean_text, content_sig):
        return False
    if not _is_subsequence(rec.clean_text, current):
        return False
    return _backup_write_verify(root, rec.path, rec.clean_text, quarantine, content_sig)


def apply_suggested(repo, sug: "Suggested", quarantine: Path, content_sig) -> bool:
    """Apply a COMPUTED (non-git-corroborated) concealment-seam strip — the Tier-2 write.
    Byte-for-byte the SAME safety as an excised `Recovery` (re-prove `_seam_strip` on the live file,
    then backup → write → verify-or-revert, all via the shared `_apply_seam_excision`). The ONLY
    difference is that no clean ancestor corroborated it, so the CALLER lands it as a separate,
    review-required commit and keeps the run needs-review — the operator's PR review is the trust
    anchor for the one residual the git-match would otherwise close (a scanner-invisible injection
    in the kept code). Never auto-merged; never presented as a corroborated fix.

    A "restore"-mode Suggested (a clean 3-way-merge version for a file born via an evil merge)
    re-proves through the whole-file restore gates instead of `_seam_strip` — same write safety, still
    review-required."""
    if getattr(sug, "apply_mode", "seam") == "restore":
        return _apply_whole_file_restore(Path(repo), sug.path, sug.excised_text, quarantine, content_sig)
    return _apply_seam_excision(Path(repo), sug.path, sug.excised_text, quarantine, content_sig)
