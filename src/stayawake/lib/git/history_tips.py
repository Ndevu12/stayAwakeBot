#!/usr/bin/env python3
"""The refs, stash entries and checkouts that keep a repository's history reachable."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import UNTRUSTED, answer, run


_PER_CHECKOUT = ("refs/bisect/", "refs/worktree/", "refs/rewritten/")
_PSEUDO_REFS = ("ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD",
                "REBASE_HEAD", "BISECT_HEAD", "AUTO_MERGE")


def _pseudo_refs_in(repo: Path, gitdir: Path) -> list[tuple[str, str]] | None:
    """List the pseudo-refs one checkout holds, such as `ORIG_HEAD`, with what they point at. Takes
    the repo and the directory git keeps that checkout's refs in. Returns `(name, object id)` for
    each present, or None when git could not answer."""
    res = run(repo, [f"--git-dir={gitdir}", "cat-file", "--batch-check"],
                      context=UNTRUSTED, input_text="".join(f"{name}\n" for name in _PSEUDO_REFS))
    if res is None or res.returncode != 0:
        return None
    lines = (res.stdout or "").splitlines()
    if len(lines) != len(_PSEUDO_REFS):
        return None
    out = []
    for name, line in zip(_PSEUDO_REFS, lines):
        parts = line.split()
        if len(parts) == 3:
            out.append((name, parts[0]))
        elif parts[-1:] != ["missing"]:
            return None
    return out


def _refs_in(repo: Path, patterns: list[str], gitdir: Path | None = None) -> list[tuple[str, str]] | None:
    """List refs with their tips, leaving out a symbolic ref whose target is listed in its own right.
    Takes the repo, the ref patterns, and the directory git keeps one checkout's refs in when those
    are the ones asked for. Returns `(name, tip)` pairs, or None when git could not list them."""
    pinned = [f"--git-dir={gitdir}"] if gitdir is not None else []
    named = answer(repo, [*pinned, "for-each-ref",
                           "--format=%(refname)%00%(objectname)%00%(symref)", *patterns])
    if named is None:
        return None
    rows = [parts for parts in (line.split("\0") for line in named.splitlines())
            if len(parts) == 3 and parts[1]]
    listed = {name for name, _tip, _target in rows}
    return [(name, tip) for name, tip, target in rows if target not in listed]


def _checkout_dirs(repo: Path) -> list[tuple[str, Path]] | None:
    """Find the directory git keeps each checkout's own refs in. Takes the repo. Returns each as
    `(label, directory)`, labelled the way git addresses another checkout's refs, or None when they
    could not be found."""
    common = answer(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
    if common is None or not common.strip():
        return None
    root = Path(common.strip())
    dirs = [("main-worktree", root)]
    try:
        dirs += [(f"worktrees/{d.name}", d) for d in sorted((root / "worktrees").iterdir())
                 if d.is_dir()]
    except FileNotFoundError:
        pass
    except OSError:
        return None
    return dirs


def history_tips(repo: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """List the refs and checkouts that can still reach a commit. Takes the repo. Returns each as
    `(name, tip)`, and what could not be listed."""
    out: list[tuple[str, str]] = []
    unsure: list[str] = []
    shared = _refs_in(repo, ["refs/"])
    if shared is None:
        unsure.append("the tags, stashes and other refs")
    else:
        out += [(name, tip) for name, tip in shared if not name.startswith(_PER_CHECKOUT)]
    checkouts = _checkout_dirs(repo)
    if checkouts is None:
        unsure.append("the other checkouts' own refs")
    for label, gitdir in checkouts or []:
        own = _refs_in(repo, list(_PER_CHECKOUT), gitdir)
        pseudo = _pseudo_refs_in(repo, gitdir)
        if own is None or pseudo is None:
            unsure.append(f"the refs of {label}")
        out += [(f"{label}/{name}", tip) for name, tip in (own or []) + (pseudo or [])]
    if any(name == "refs/stash" for name, _tip in out):
        entries = answer(repo, ["rev-list", "-g", "refs/stash"])
        if entries is None:
            unsure.append("the stash entries")
        else:
            stashed = entries.split()
            out = [(name, tip) for name, tip in out if name != "refs/stash" or tip not in stashed]
            out += [(f"stash@{{{i}}}", sha) for i, sha in enumerate(stashed)]
    heads = _checkout_heads(repo)
    if heads is None:
        unsure.append("the other checkouts")
    return out + (heads or []), unsure


def _checkout_heads(repo: Path) -> list[tuple[str, str]] | None:
    """List the commit each checkout of the repository is on. Takes the repo. Returns the label and
    commit of each checkout on a commit, or None when git could not list them."""
    worktrees = answer(repo, ["worktree", "list", "--porcelain"])
    if worktrees is None:
        return None
    heads, path = [], ""
    for line in worktrees.splitlines():
        if line.startswith("worktree "):
            path = line[len("worktree "):]
        elif line.startswith("HEAD ") and line[len("HEAD "):].strip().strip("0"):
            heads.append((f"worktree {path}", line[len("HEAD "):].strip()))
    return heads
