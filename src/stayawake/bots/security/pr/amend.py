#!/usr/bin/env python3
"""`saw fix amend` — replace a confirmed merge that introduced the payload.

Bare `saw fix` is unchanged. This path is local, never `--pr`, and never moves a tag.
"""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib import git as gitutil


def _full(repo: Path, sha: str) -> str:
    return gitutil.stdout(repo, ["rev-parse", sha]).strip() or sha


def _confirmed_merges(scan) -> list:
    found = []
    seen: set[str] = set()
    for f in scan.findings:
        if getattr(f, "vector", None) != "evil-merge":
            continue
        if getattr(f, "confidence", None) != CONFIRMED:
            continue
        sha = getattr(f, "commit_sha", None) or getattr(f, "path", None)
        if not sha or sha in seen:
            continue
        seen.add(sha)
        found.append(f)
    return found


def amend_repo(repo: Path, opts, signatures, allowlist) -> str:
    """Replace one confirmed merge on the current branch. Returns the operator line."""
    display = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    if not gitutil.is_git_repo(repo):
        return f"{display}: not a git repository"
    branch = gitamend.branch_name(repo)
    if not branch:
        return f"{display}: detached HEAD — check out a branch first"
    if gitamend.is_dirty(repo):
        return f"{display}: working tree is not clean — commit or stash first"

    scan = scan_target(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)
    if scan.error:
        return f"{display}: scan did not finish — nothing was replaced"
    merges = _confirmed_merges(scan)
    if not merges:
        return f"{display}: no confirmed merge to replace"
    if len(merges) > 1:
        shas = ", ".join(_full(repo, getattr(f, "commit_sha", None) or f.path)[:12] for f in merges)
        return f"{display}: {len(merges)} confirmed merges on this branch — not replaced ({shas})"

    finding = merges[0]
    merge = _full(repo, finding.commit_sha or finding.path)
    head = _full(repo, "HEAD")
    if not gitamend.merge_is_on_head(repo, merge, head):
        return (f"{display}: confirmed merge {merge[:12]} is not on this branch "
                "— nothing was replaced")

    related = tuple(getattr(finding, "related_paths", ()) or ())
    new_merge = gitamend.reconstruct_merge(repo, merge)
    if new_merge is None:
        return (f"{display}: could not replace merge {merge[:12]} "
                "— the clean merge could not be established")

    gitamend.capture_bundle(repo, merge, head, related)
    tags = gitutil.stdout(repo, ["tag", "--points-at", merge]).split()
    new_head = gitamend.replay_suffix(repo, branch, merge, new_merge, head)
    if new_head is None:
        return f"{display}: replay failed — branch '{branch}' was left as it stood"

    n = len(gitamend.descendant_shas(repo, merge, head))
    after = (f"{n} later commit(s) replayed" if n else "the branch now points at the replacement")
    tag_note = ("; tags still point at the previous commit"
                if tags else "")
    return (f"{display}: replaced merge {merge[:12]} on '{branch}' ({after}). "
            f"The previous objects remain until collected; forks are unaffected{tag_note}")
