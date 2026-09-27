#!/usr/bin/env python3
"""Capture the objects a history rewrite is about to orphan, as a git bundle that has been read
back before the caller is told it exists.

A record of object IDs is a record of POINTERS: the next `git gc` prunes what they point at and
the evidence base is gone. A bundle carries the objects themselves, so the captured commits can
be restored into any clone afterwards. The destination is the caller's; it has to be somewhere
that outlives the rewrite, which rules out both the worktree (a new file there makes the tree
dirty and the ref move is then refused) and a linked worktree's admin directory (git deletes it).

The capture spans exactly what the rewrite orphans (`old --not new`) and no more: a bundle of a
whole history is unusable on a large repository, and re-reading it would not distinguish the
objects the rewrite removed from the ones it left alone.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.borrowed import borrow
from stayawake.lib.git.run import UNTRUSTED, run, stdout

CAPTURE_REF_PREFIX = "refs/saw-capture/"


@dataclass(frozen=True)
class BundleResult:
    """What `capture_bundle` established, so the caller can abort the rewrite on anything short
    of a bundle it has read back.

    `verified` means git parsed the bundle's header and accepted its prerequisites against the
    repository. It does NOT mean the packfile was read: `git bundle verify` does not walk it, and a
    truncated pack still verifies. It is the strongest cheap check, not a guarantee of readback.

    `ok` is the only field a caller should gate on. Nothing orphaned is an EMPTY capture, not a
    failure: `ok` is True with `path` None and `verified` False, because no bundle was written
    and none could therefore have verified. Every other `verified=False` carries a `reason`, and
    keeps `path` when a file was written but did not read back — an operator can still inspect it.

    `commits` and `objects` describe the orphaned range as git counted it, and stay 0 when git
    could not answer.
    """
    path: Path | None
    verified: bool
    commits: int
    objects: int
    reason: str

    @property
    def ok(self) -> bool:
        """True when the evidence is in hand — including an empty capture, which has none to be."""
        return not self.reason


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _range_args(tips: list[str], exclusions: list[str]) -> list[str]:
    """Rev-list arguments for everything reachable from `tips` and from none of `exclusions`.

    The exclusions are pooled rather than paired off against a single tip, because that pooled
    set is precisely what the rewrite orphans: once every branch has moved, an object still
    reachable from ANY new tip has not been orphaned by anything and needs no capture.
    """
    return [*tips, "--not", *exclusions] if exclusions else list(tips)


def _count(repo: str | Path, args: list[str]) -> int | None:
    """The integer a counting git command printed, or None when it could not answer."""
    res = run(repo, args, context=UNTRUSTED)
    if res is None or res.returncode != 0:
        return None
    text = (res.stdout or "").strip()
    return int(text) if text.isdigit() else None


def _write_bundle(repo: str | Path, old_tips: list[str], new_tips: list[str],
                  destination: Path) -> tuple[bool, str]:
    """Write the bundle from a saw-owned repository that reads `repo`'s objects through `alternates`,
    with a ref there for each old tip, and read it back there; `repo` is never written to.
    Returns `(written, reason)`: reason '' on success, else an operator-readable one, with
    `written` saying whether a file was left to inspect."""
    try:
        with borrow(repo) as stage:
            capture_refs = []
            for tip in old_tips:
                ref = f"{CAPTURE_REF_PREFIX}{tip}"
                if not _ok(stage.run(["update-ref", ref, tip])):
                    return False, f"the orphaned tip {tip[:12]} could not be named for capture"
                capture_refs.append(ref)
            res = stage.run(["bundle", "create", str(destination),
                             *_range_args(capture_refs, new_tips)])
            if res is None:
                return False, "git bundle create could not run"
            if res.returncode != 0:
                return False, f"the capture could not be written: {(res.stderr or res.stdout or '').strip()}"
            checked = stage.run(["bundle", "verify", str(destination)])
            if checked is None:
                return True, "git bundle verify could not run"
            if checked.returncode != 0:
                detail = (checked.stderr or checked.stdout or "").strip()
                return True, f"the capture did not read back: {detail}"
            return True, ""
    except OSError as exc:
        return False, f"the captured objects could not be reached: {exc}"


def _ok(res) -> bool:
    return res is not None and res.returncode == 0


def capture_bundle(repo: str | Path, orphaned: list[tuple[str, str]],
                   destination: str | Path) -> BundleResult:
    """Bundle every object that moving each `(old_tip, new_tip)` will make unreachable into
    `destination`, then read the written file back with `git bundle verify`.

    Written is not readable: the bundle is only reported as captured once git has parsed its
    header and accepted its prerequisites against `repo` — see `BundleResult` for what that check
    does and does not establish. Ordinary failures — an unwritable destination, a
    git that will not run, a file that does not read back — are RETURNED, never raised, so the
    caller can abort with every object still in place.

    A pair whose two tips are the same, or whose old tip is already an ancestor of the new one,
    orphans nothing; when no pair orphans anything the result is an empty capture, not an error.
    """
    dest = Path(destination)
    pairs = [(str(old).strip(), str(new).strip()) for old, new in orphaned]
    if not pairs:
        return BundleResult(None, False, 0, 0, "")
    incomplete = [old or "?" for old, new in pairs if not (old and new)]
    if incomplete:
        return BundleResult(None, False, 0, 0,
                            "every orphaned pair needs both tips; a missing new tip would "
                            f"capture a whole history ({', '.join(incomplete)})")

    old_tips = _unique([old for old, _ in pairs])
    new_tips = _unique([new for _, new in pairs])
    orphaned_range = _range_args(old_tips, new_tips)
    commits = _count(repo, ["rev-list", "--count", *orphaned_range])
    if commits is None:
        return BundleResult(None, False, 0, 0, "the orphaned range could not be listed")
    if commits == 0:
        return BundleResult(None, False, 0, 0, "")
    objects = _count(repo, ["rev-list", "--objects", "--count", *orphaned_range]) or 0

    if not stdout(repo, ["rev-parse", "--git-dir"], context=UNTRUSTED).strip():
        return BundleResult(None, False, commits, objects,
                            f"{repo} is not a git repository")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return BundleResult(None, False, commits, objects,
                            f"the capture destination could not be created: {exc}")

    written, failure = _write_bundle(repo, old_tips, new_tips, dest)
    if failure:
        return BundleResult(dest if written else None, False, commits, objects, failure)
    return BundleResult(dest, True, commits, objects, "")
