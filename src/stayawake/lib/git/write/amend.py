#!/usr/bin/env python3
"""Replace a named commit that still carries the payload, then replay the bounded suffix
on every branch that reached it. Capture the previous identifiers before any ref moves."""
from __future__ import annotations

import os
from pathlib import Path

from stayawake.lib.git.query import parents

from stayawake.utils import scratch
from stayawake.lib.git.run import UNTRUSTED, run, run_ok, stdout_bytes
from stayawake.lib.git.write import working_tree
from stayawake.lib.git.write.checkouts import checked_out_at
from stayawake.lib.git.write.replace import Replacement, replacement_tree
from stayawake.lib.git.write.sign import (SigningStatus, sign_flags, signing_args, signing_env,
                                          signing_status)


_ZERO = "0" * 40


def changes_in_the_way(worktree: str | Path, commit: str):
    """The uncommitted changes in `worktree` a move to `commit` would overwrite
    (`working_tree.changes_in_the_way`)."""
    return working_tree.changes_in_the_way(worktree, commit)


def is_dirty(repo: str | Path) -> bool:
    """Whether the checkout at `repo` holds anything its HEAD does not (`working_tree.is_dirty`)."""
    return working_tree.is_dirty(repo)


def _differing_paths(repo: str | Path, base: str, target: str) -> list[str] | None:
    """Repo-relative paths where two commits/trees differ, or None when git could not compare
    them — each caller decides what an unanswerable comparison means.

    `-z` is load-bearing: git otherwise quotes a non-ASCII path, so a payload under such a
    directory would be reported under a name matching nothing the caller holds. Renames stay
    off — the claim is about the content at a path, not about identity across a move.
    """
    res = run(repo, ["diff", "--no-textconv", "--no-ext-diff", "--name-only", "--no-renames",
                     "-z", base, target], context=UNTRUSTED)
    if res is None or res.returncode != 0:
        return None
    return sorted({p for p in (res.stdout or "").split("\0") if p})


def _tree_paths(repo: str | Path, treeish: str) -> list[str]:
    res = run(repo, ["ls-tree", "-r", "--name-only", "-z", treeish], context=UNTRUSTED)
    if res is None or res.returncode != 0:
        return []
    return sorted({p for p in (res.stdout or "").split("\0") if p})


_CARRIED_HEADERS = (b"tree", b"parent", b"author", b"committer", b"gpgsig")


def _uncarried_headers(headers: bytes) -> list[str]:
    """Header names this rewrite cannot reproduce. `gpgsig` is expected — the replacement is a
    different object and gets its own signature — but an `encoding` or a `mergetag` says
    something about the commit that would silently disappear."""
    seen = []
    for line in headers.split(b"\n"):
        if line.startswith(b" ") or not line.strip():
            continue                     # a continuation of the header above it
        name = line.split(b" ", 1)[0]
        if name and name not in _CARRIED_HEADERS:
            seen.append(name.decode("ascii", "replace"))
    return sorted(set(seen))


def _author_env(headers: bytes) -> dict | None:
    """The author of the commit being replaced, exactly as recorded.

    Every field is set even when empty: skipping an empty email let `commit-tree` fall back to
    the OPERATOR's identity and write them into the author slot of a commit they did not author.
    The date is the raw `<timestamp> <tz>`, so git's "timezone unknown" `-0000` is not normalised
    to `+0000`. `surrogateescape` carries bytes that are not valid UTF-8 through the environment
    unchanged.
    """
    line = next((ln for ln in headers.split(b"\n") if ln.startswith(b"author ")), None)
    if line is None:
        return None
    rest = line[len(b"author "):]
    open_at = rest.rfind(b" <")
    close_at = rest.find(b">", open_at + 1) if open_at >= 0 else -1
    if open_at < 0 or close_at < 0:
        return None
    env = dict(os.environ)
    env["GIT_AUTHOR_NAME"] = rest[:open_at].decode("utf-8", "surrogateescape")
    env["GIT_AUTHOR_EMAIL"] = rest[open_at + 2:close_at].decode("utf-8", "surrogateescape")
    env["GIT_AUTHOR_DATE"] = rest[close_at + 1:].strip().decode("utf-8", "surrogateescape")
    return env


def replacement_commit(repo: str | Path, commit: str, flagged_paths,
                       signing: SigningStatus | None = None,
                       still_carries=None) -> Replacement:
    """`commit` with the payload removed: same parents, same message, same author, and a tree
    that is its own with only the flagged paths put back to what they should have been.

    It is not rebuilt from its parents. Everything the commit contributed beyond the payload — a
    conflict resolution, an edit made during the merge, a file it deleted — is what the recorded
    tree already holds, and replacing that tree wholesale is what used to make this refuse.
    """
    signing = signing_status(repo) if signing is None else signing
    corrected = replacement_tree(repo, commit, flagged_paths, still_carries)
    if not corrected.ok:
        return corrected
    sha, kind, refusal = rewrite_commit(repo, commit, corrected.tree,
                                        parents(repo, commit), signing)
    if not sha:
        return Replacement(kind=kind, refusal=refusal)
    return Replacement(tree=corrected.tree, sha=sha, plan=corrected.plan,
                       reverted=corrected.reverted, removed=corrected.removed,
                       recovered=corrected.recovered)


def rewrite_commit(repo: str | Path, commit: str, tree: str, new_parents: list[str],
                   signing: SigningStatus | None = None) -> tuple[str, str, str]:
    """`commit` rebuilt on `new_parents` with `tree`, keeping its message, author and shape.

    Returns `(sha, kind, refusal)`; `sha` is empty exactly when `kind` explains why. Used for the
    commit being replaced and for every commit after it, so a rebuilt suffix gets the same
    fidelity guarantees rather than whatever a replay happened to preserve.
    """
    signing = signing_status(repo) if signing is None else signing
    raw = stdout_bytes(repo, ["cat-file", "commit", commit], context=UNTRUSTED)
    if not raw:
        return "", "message", "the original commit could not be read"
    headers, _, body = raw.partition(b"\n\n")
    uncarried = _uncarried_headers(headers)
    if uncarried:
        return "", "headers", ("this commit records " + ", ".join(uncarried)
                               + ", which a replacement cannot carry")
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        # MEASURED: `commit-tree` warns "commit message did not conform to UTF-8" and converts
        # from the LOCALE charset, so the replacement's message depends on the machine that ran
        # it. There is no encoding to convert back from once the header is gone.
        return "", "message-encoding", ("this commit's message is not UTF-8 and a replacement "
                                        "cannot reproduce it")
    env = _author_env(headers)
    if env is None:
        return "", "message", "the original author could not be read"
    parent_args = [arg for p in new_parents for arg in ("-p", p)]
    msg_path = None
    try:
        # The BODY BYTES, written verbatim. `--format=%B` appends a newline of its own and decodes
        # through `errors="replace"`, so a message in a legacy encoding came back as U+FFFD and
        # every replacement grew a trailing blank line — both irreversible once pushed.
        msg_path = str(scratch.new_file("a commit message"))
        with open(msg_path, "wb") as fh:
            fh.write(body)
        res = run(repo, [*signing_args(signing), "commit-tree",
                         *sign_flags(signing, "commit-tree"), tree, *parent_args, "-F", msg_path],
                  env=signing_env(repo, env), context=UNTRUSTED)
    finally:
        if msg_path:
            try:
                os.unlink(msg_path)
            except OSError:
                pass
    if res is None or res.returncode != 0:
        return "", "write", "the replacement commit could not be written"
    sha = (res.stdout or "").strip()
    if not sha:
        return "", "write", "the replacement commit could not be written"
    return sha, "", ""


def discarded_delta(repo: str | Path, merge_sha: str, reconstructed_tree: str) -> list[str]:
    """Every repo-relative path where the reconstruction fails to reproduce what `merge_sha`
    recorded — the part of the merge's contribution that replacing it destroys.

    The CONFIRMED signature proves that SOME content the merge introduced is payload; it never
    proves that all of it is. A conflict resolution, an edit made by hand during the merge, and
    a file the merge deleted all land here beside the payload. Reporting them is all this does:
    refusing, or disclosing and going ahead, is the caller's decision.

    When git cannot compare the two, every path the merge recorded is returned — nothing can be
    shown to survive, and an empty list would read as "the reconstruction loses nothing".
    """
    delta = _differing_paths(repo, merge_sha, reconstructed_tree)
    return _tree_paths(repo, merge_sha) if delta is None else delta


class AmendUnwindFailed(RuntimeError):
    """A branch was moved and could not be put back. The repository is in neither state, so the
    caller must not continue and must not describe the outcome as though it knew what happened."""

    def __init__(self, repo, *, unrestored: list[str], moved: dict[str, str]):
        self.repo = str(repo)
        self.unrestored = list(unrestored)
        self.moved = dict(moved)
        super().__init__(f"{self.repo}: could not restore {', '.join(self.unrestored)}")


def restore_branches(repo: str | Path, heads: list[tuple[str, str, str]],
                     moved: dict[str, str], failed: list[str],
                     keep: dict[str, frozenset[str]] | None = None,
                     staging: dict[str, dict] | None = None) -> list[str]:
    """Put `failed` branches back to their captured tips. Created local heads are deleted. `keep`
    names, per branch, the uncommitted changes its checkout keeps across the move, and `staging`
    what was staged at them before it, which is put back.

    Returns the names it could NOT restore — empty when every one is back. It used to return
    nothing, so a refused restore was silent and the operator was told branches were put back
    when one was not."""
    by_name = {name: cas_old for name, _tip, cas_old in heads}
    unrestored: list[str] = []
    for name in failed:
        new_tip = moved.get(name)
        cas_old = by_name.get(name)
        if not new_tip or cas_old is None:
            continue
        if cas_old == _ZERO:
            if not run_ok(repo, ["update-ref", "-d", f"refs/heads/{name}"], context=UNTRUSTED):
                unrestored.append(name)
            continue
        try:
            if not point_branch_at(repo, name, cas_old, new_tip, keep=(keep or {}).get(name),
                                   restage=(staging or {}).get(name)):
                unrestored.append(name)
        except AmendUnwindFailed:
            unrestored.append(name)
    return unrestored


def checkout_holding(repo: str | Path, branch: str) -> Path | None:
    """The working tree with `branch` checked out, or None when no checkout has it.

    Every checkout, not just `repo`'s own. `git update-ref` will happily move a branch that a
    LINKED worktree has checked out, and that worktree's tree is then left at the old content
    with the difference staged — so asking only `symbolic-ref HEAD` here answered for one
    checkout and silently skipped the rest. Raises OSError when that cannot be established.
    """
    holder = checked_out_at(repo, branch)
    return None if holder is None else holder.worktree


def point_branch_at(repo: str | Path, branch: str, new: str, old: str,
                    keep: frozenset[str] | None = None, staging: dict | None = None,
                    restage: dict | None = None) -> bool:
    """Compare-and-swap `refs/heads/branch` from `old` to `new`.

    The checkout holding that branch — any checkout, not only this one — follows it, so this
    refuses outright, before the ref moves, while that tree holds uncommitted work. Given `keep`,
    uncommitted work the move does not overwrite comes along, and so does work on the paths `keep`
    names: those stay as they are on disk, and what was staged there stays staged. `staging`
    receives what was staged at each kept path; `restage` puts such a record back exactly, for a
    move that undoes an earlier one. The guard sits
    here rather than with the caller because the tree is rewritten here: a checked-out branch
    reaches this function from the amend path, from the restore path, and from anything added
    next, and only one of those has to forget the check for the work to be gone.
    """
    try:
        holder = checked_out_at(repo, branch)
    except OSError:
        return False
    before_dirty = None
    kept: frozenset[bytes] = frozenset()
    if holder is not None:
        if keep is None:
            if is_dirty(holder.worktree):
                return False
        else:
            in_way = working_tree.changes_in_the_way(holder.worktree, new)
            if in_way is None or in_way.blocking or not set(in_way.carryable) <= set(keep):
                return False
            kept = frozenset(os.fsencode(p) for p in
                             set(keep) | set(in_way.carryable) | set(in_way.already))
        before_dirty = working_tree.uncommitted_paths(holder.worktree)
        if before_dirty is None:
            return False
    move = None
    if holder is not None:
        move = working_tree.PreparedMove(Path(repo), holder, old, new, keep=kept, restage=restage)
        if not move.prepare():
            move.release()
            return False
        if staging is not None:
            staging.update(move.kept_entries)
    if not run_ok(repo, ["update-ref", f"refs/heads/{branch}", new, old], context=UNTRUSTED):
        if move is not None:
            move.release()
        return False
    if move is None:
        return True
    if move.apply():
        move.release()
        return True
    # The ref moved and the tree did not: both go back before a refusal is reported.
    restored = move.restore_files()
    move.release()
    if run_ok(repo, ["update-ref", f"refs/heads/{branch}", old, new], context=UNTRUSTED) \
            and restored and working_tree.uncommitted_paths(holder.worktree) == before_dirty:
        return False
    raise AmendUnwindFailed(repo, unrestored=[branch], moved={branch: new})


def point_branches(repo: str | Path, heads: list[tuple[str, str, str]],
                   new_tips: dict[str, str],
                   keep: dict[str, frozenset[str]] | None = None,
                   staging: dict[str, dict] | None = None) -> dict[str, str] | None:
    """Repoint every `(name, replay_tip, cas_old)` at the tip the rebuild produced for it. `keep`
    names, per branch, the uncommitted changes its checkout keeps across the move; `staging`
    receives, per branch, what was staged at them, for an undo to put back.

    None when a compare-and-swap fails. A CAS that failed part way used to leave the branches
    before it moved while the caller reported that nothing had; anything already moved is put
    back before returning.
    """
    moved: dict[str, str] = {}
    for name, tip, cas_old in heads:
        new_tip = new_tips.get(tip)
        if not new_tip:
            continue
        recorded = staging.setdefault(name, {}) if staging is not None else None
        if not point_branch_at(repo, name, new_tip, cas_old, keep=(keep or {}).get(name),
                               staging=recorded):
            unrestored = restore_branches(repo, heads, moved, list(moved), keep, staging)
            if unrestored:
                raise AmendUnwindFailed(repo, unrestored=unrestored, moved=moved)
            return None
        moved[name] = new_tip
    return moved
