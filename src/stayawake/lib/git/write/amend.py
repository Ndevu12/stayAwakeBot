#!/usr/bin/env python3
"""Replace a named commit that still carries the payload, then replay the bounded suffix
on every branch that reached it. Capture the previous identifiers before any ref moves."""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from stayawake.lib.git.merge.tree import auto_merge
from stayawake.lib.git.query import parents, commit_meta, is_ancestor, branches_carrying
from stayawake.lib.git.run import run, run_ok, stdout, stdout_bytes
from stayawake.lib.git.write.replace import Replacement, replacement_tree
from stayawake.lib.git.write.sign import (SigningStatus, sign_flags, signing_args, signing_env,
                                          signing_status)
from stayawake.lib.git.write.worktree import add_worktree, remove_worktree


_ZERO = "0" * 40


def is_dirty(repo: str | Path) -> bool:
    return bool(stdout(repo, ["status", "--porcelain"]).strip())


def descendant_shas(repo: str | Path, merge: str, head: str = "HEAD") -> list[str]:
    """Commits after `merge` on the way to `head`, oldest first. Empty when `merge` is `head`.

    Ordered by the graph, not by date: a replay stamps every commit with the same committer
    second, so date order would not line an original up against the commit that replaced it.
    """
    out = stdout(repo, ["rev-list", "--reverse", "--topo-order", "--ancestry-path",
                        f"{merge}..{head}"])
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def _differing_paths(repo: str | Path, base: str, target: str) -> list[str] | None:
    """Repo-relative paths where two commits/trees differ, or None when git could not compare
    them — each caller decides what an unanswerable comparison means.

    `-z` is load-bearing: git otherwise quotes a non-ASCII path, so a payload under such a
    directory would be reported under a name matching nothing the caller holds. Renames stay
    off — the claim is about the content at a path, not about identity across a move.
    """
    res = run(repo, ["diff", "--name-only", "--no-renames", "-z", base, target])
    if res is None or res.returncode != 0:
        return None
    return sorted({p for p in (res.stdout or "").split("\0") if p})


def _message(repo: str | Path, sha: str) -> str:
    return stdout(repo, ["show", "-s", "--format=%B", sha])


def _tree_paths(repo: str | Path, treeish: str) -> list[str]:
    res = run(repo, ["ls-tree", "-r", "--name-only", "-z", treeish])
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
    ps = parents(repo, commit)
    raw = stdout_bytes(repo, ["cat-file", "commit", commit])
    if not raw:
        return Replacement(kind="message", refusal="the original commit could not be read")
    headers, _, body = raw.partition(b"\n\n")
    uncarried = _uncarried_headers(headers)
    if uncarried:
        return Replacement(kind="headers",
                           refusal="this commit records " + ", ".join(uncarried)
                                   + ", which a replacement cannot carry")
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        # MEASURED: `commit-tree` warns "commit message did not conform to UTF-8" and converts
        # from the LOCALE charset, so the replacement's message depends on the machine that ran
        # it. There is no encoding to convert back from once the header is gone.
        return Replacement(kind="message-encoding",
                           refusal="this commit's message is not UTF-8 and a replacement cannot "
                                   "reproduce it")
    env = _author_env(headers)
    if env is None:
        return Replacement(kind="message", refusal="the original author could not be read")
    parent_args = [arg for p in ps for arg in ("-p", p)]
    msg_path = None
    res = None
    try:
        # The BODY BYTES, written verbatim. `--format=%B` appends a newline of its own and decodes
        # through `errors="replace"`, so a message in a legacy encoding came back as U+FFFD and
        # every replacement grew a trailing blank line — both irreversible once pushed.
        with tempfile.NamedTemporaryFile("wb", delete=False) as fh:
            fh.write(body)
            msg_path = fh.name
        res = run(repo, [*signing_args(signing), "commit-tree",
                         *sign_flags(signing, "commit-tree"), corrected.tree,
                         *parent_args, "-F", msg_path],
                  env=signing_env(repo, env))
    finally:
        if msg_path:
            try:
                os.unlink(msg_path)
            except OSError:
                pass
    if res is None or res.returncode != 0:
        return Replacement(kind="write", refusal="the replacement commit could not be written")
    sha = (res.stdout or "").strip()
    if not sha:
        return Replacement(kind="write", refusal="the replacement commit could not be written")
    return Replacement(tree=corrected.tree, sha=sha, reverted=corrected.reverted,
                       removed=corrected.removed)


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


def capture_bundle(repo: str | Path, merge_sha: str, related: tuple[str, ...],
                   branches: dict[str, str]) -> Path:
    """Write the identifiers of the commit being replaced, before any ref moves."""
    root = Path(repo) / ".git" / "saw-amend" / merge_sha[:12]
    root.mkdir(parents=True, exist_ok=True)
    blobs = {}
    for path in related:
        oid = stdout(repo, ["rev-parse", f"{merge_sha}:{path}"]).strip()
        if oid:
            blobs[path] = oid
    payload = {
        "commit": merge_sha,
        "branches": branches,
        "blobs": blobs,
        "meta": commit_meta(repo, merge_sha),
    }
    (root / "capture.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return root


class AmendUnwindFailed(RuntimeError):
    """A branch was moved and could not be put back. The repository is in neither state, so the
    caller must not continue and must not describe the outcome as though it knew what happened."""

    def __init__(self, repo, *, unrestored: list[str], moved: dict[str, str]):
        self.repo = str(repo)
        self.unrestored = list(unrestored)
        self.moved = dict(moved)
        super().__init__(f"{self.repo}: could not restore {', '.join(self.unrestored)}")


def restore_branches(repo: str | Path, heads: list[tuple[str, str, str]],
                     moved: dict[str, str], failed: list[str]) -> list[str]:
    """Put `failed` branches back to their captured tips. Created local heads are deleted.

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
            if not run_ok(repo, ["update-ref", "-d", f"refs/heads/{name}"]):
                unrestored.append(name)
            continue
        try:
            if not point_branch_at(repo, name, cas_old, new_tip):
                unrestored.append(name)
        except AmendUnwindFailed:
            unrestored.append(name)
    return unrestored


def checkout_holding(repo: str | Path, branch: str) -> Path | None:
    """The worktree with `branch` checked out, or None when no worktree has it.

    Every worktree, not just `repo`'s own. `git update-ref` will happily move a branch that a
    LINKED worktree has checked out, and that worktree's tree is then left at the old content
    with the difference staged — so asking only `symbolic-ref HEAD` here answered for one
    checkout and silently skipped the rest.
    """
    listed = stdout(repo, ["worktree", "list", "--porcelain"])
    path: str | None = None
    for line in listed.splitlines():
        if line.startswith("worktree "):
            path = line[len("worktree "):].strip()
        elif line.strip() == f"branch refs/heads/{branch}" and path:
            return Path(path)
    return None


def point_branch_at(repo: str | Path, branch: str, new: str, old: str) -> bool:
    """Compare-and-swap `refs/heads/branch` from `old` to `new`.

    The worktree holding that branch — any worktree, not only this one — is reset with it, so
    this refuses outright, before the ref moves, while that tree holds uncommitted work. The
    guard sits here rather than with the caller because `reset --hard` is here: a checked-out
    branch reaches this function from the amend path, from the restore path, and from anything
    added next, and only one of those has to forget the check for the work to be gone.
    """
    holder = checkout_holding(repo, branch)
    if holder is not None and is_dirty(holder):
        return False
    if not run_ok(repo, ["update-ref", f"refs/heads/{branch}", new, old]):
        return False
    if holder is None:
        return True
    if run_ok(holder, ["reset", "--hard", "--quiet", "HEAD"]):
        return True
    # The ref is at `new` and the tree is not. A held `index.lock` or an unwritable file is enough
    # (measured: `update-ref` succeeds, `reset` exits 128). Returning False from here told the
    # caller nothing had moved while the branch sat on the replacement with the old content staged
    # as a change — the operator's next commit would put the payload back on top of the clean
    # history. So the ref goes back, and a refusal is only reported once the branch AND the tree
    # are demonstrably where they started.
    if run_ok(repo, ["update-ref", f"refs/heads/{branch}", old, new]) and not is_dirty(holder):
        return False
    raise AmendUnwindFailed(repo, unrestored=[branch], moved={branch: new})


def replayed_head(repo: str | Path, old_merge: str, new_merge: str, old_head: str,
                  signing: SigningStatus | None = None) -> str | None:
    """The SHA after replaying `old_head`'s suffix onto `new_merge`. No ref is moved.

    The suffix keeps whatever signing the repository is configured for: replaying signed commits
    unsigned strips the very property the history was published with."""
    signing = signing_status(repo) if signing is None else signing
    desc = descendant_shas(repo, old_merge, old_head)
    if not desc:
        return new_merge
    wt = Path(tempfile.mkdtemp(prefix="sab-amend-"))
    wt.rmdir()
    label = f"saw-amend/{os.urandom(4).hex()}"
    if not add_worktree(repo, wt, label, old_head):
        return None
    try:
        if not run_ok(wt, [*signing_args(signing), "rebase", *sign_flags(signing, "rebase"),
                           "--rebase-merges", "--onto", new_merge, old_merge],
                      env=signing_env(repo, dict(os.environ, GIT_EDITOR="true",
                                                 GIT_SEQUENCE_EDITOR="true",
                                                 GIT_TERMINAL_PROMPT="0"))):
            run_ok(wt, ["rebase", "--abort"])
            return None
        new_head = stdout(wt, ["rev-parse", "HEAD"]).strip()
        return new_head or None
    finally:
        remove_worktree(repo, wt)
        run_ok(repo, ["branch", "-D", label])
        try:
            wt.rmdir()
        except OSError:
            pass


def replay_is_faithful(repo: str | Path, old_head: str, new_head: str, old_base: str,
                       new_base: str, allowed_paths: Iterable[str]) -> tuple[bool, list[str]]:
    """Whether the replayed suffix carries the same content as the suffix it replaced, once the
    paths the replacement itself changed (`allowed_paths`) are set aside.

    `--rebase-merges` rebuilds a merge in the suffix by merging its parents again. A conflict
    aborts the rebase and is safe; a clean re-merge is not, because it silently substitutes
    git's automatic answer for whatever was committed by hand into that merge — in a commit
    nobody flagged. So the replay is walked against the original commit for commit.

    Returns `(faithful, report)` with `<old> -> <new>: <path>` lines. It reports; it does not
    abort. Two limits are deliberate: sequences that cannot be walked pairwise are reported
    unfaithful rather than assumed clean, and a commit reached only through a suffix merge's
    second parent is observed through that merge's tree, not on its own.
    """
    old_seq = descendant_shas(repo, old_base, old_head)
    new_seq = descendant_shas(repo, new_base, new_head)
    if len(old_seq) != len(new_seq):
        return False, [f"replay produced {len(new_seq)} commits for {len(old_seq)} originals"]
    allowed = set(allowed_paths)
    report: list[str] = []
    for old_sha, new_sha in zip(old_seq, new_seq):
        pair = f"{old_sha[:12]} -> {new_sha[:12]}"
        if _message(repo, old_sha) != _message(repo, new_sha):
            report.append(f"{pair}: replayed commit does not correspond to the original")
            continue
        differing = _differing_paths(repo, old_sha, new_sha)
        if differing is None:
            report.append(f"{pair}: trees could not be compared")
            continue
        report += [f"{pair}: {path}" for path in differing if path not in allowed]
    return not report, report


def apply_replacement(repo: str | Path, old_commit: str, new_commit: str,
                      heads: list[tuple[str, str, str]],
                      signing: SigningStatus | None = None) -> dict[str, str] | None:
    """Repoint every `(name, replay_tip, cas_old)` onto `new_commit`. None if any replay fails
    before refs move.

    A compare-and-swap that fails part way used to leave the branches before it moved while the
    caller reported that nothing had. Anything already moved is put back before returning."""
    by_tip: dict[str, list[tuple[str, str]]] = {}
    for name, tip, cas_old in heads:
        by_tip.setdefault(tip, []).append((name, cas_old))
    planned: dict[str, tuple[str, str]] = {}
    for tip, named in by_tip.items():
        new_tip = replayed_head(repo, old_commit, new_commit, tip, signing)
        if new_tip is None:
            return None
        for name, cas_old in named:
            planned[name] = (cas_old, new_tip)
    moved: dict[str, str] = {}
    for name, (cas_old, new_tip) in planned.items():
        if not point_branch_at(repo, name, new_tip, cas_old):
            unrestored = restore_branches(repo, heads, moved, list(moved))
            if unrestored:
                raise AmendUnwindFailed(repo, unrestored=unrestored, moved=moved)
            return None
        moved[name] = new_tip
    return moved


def replay_suffix(repo: str | Path, branch: str, old_merge: str, new_merge: str,
                  old_head: str) -> str | None:
    """Replay commits after `old_merge` onto `new_merge` and move `branch`. Returns the new
    tip, or None on failure."""
    cas_old = stdout(repo, ["rev-parse", f"refs/heads/{branch}"]).strip() or _ZERO
    moved = apply_replacement(repo, old_merge, new_merge, [(branch, old_head, cas_old)])
    return moved.get(branch) if moved else None


def merge_is_on_head(repo: str | Path, merge_sha: str, head: str = "HEAD") -> bool:
    full = stdout(repo, ["rev-parse", merge_sha]).strip()
    tip = stdout(repo, ["rev-parse", head]).strip()
    if not full or not tip:
        return False
    return full == tip or is_ancestor(repo, full, tip)


def carrying_branches(repo: str | Path, sha: str) -> list[tuple[str, str, str]]:
    """Local and origin branches that still reach `sha`."""
    return branches_carrying(repo, sha)
