#!/usr/bin/env python3
"""Read-only git plumbing helpers (subprocess-based, no third-party deps).

Single responsibility: answer questions about a repository's history and trees
without ever executing repository code. Used mainly by the evil-merge detector.
"""
from __future__ import annotations

import contextlib
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

_HOST = "github.com"


@contextlib.contextmanager
def github_https_auth(token: str | None):
    """Yield (url_prefix, env) for authenticated GitHub HTTPS that keeps the token OUT of
    the URL and process args — so it can't leak via argv, `ps`, git's own error output,
    or anything we might log.

    With a token (POSIX), GIT_ASKPASS points at a throwaway 0700 script that reads the
    token from the child env, and the URL prefix carries only the username
    (`https://x-access-token@github.com/`). The secret therefore lives only in the child
    environment, never in argv/URLs/files. On Windows (no POSIX askpass) and when there
    is no token, it falls back to the prior behaviour.

        with github_https_auth(token) as (prefix, env):
            subprocess.run(["git", "clone", f"{prefix}{slug}.git", dst], env=env, ...)
    """
    base_env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_EDITOR="true")
    if not token:
        yield f"https://{_HOST}/", base_env
        return
    if os.name == "nt":  # no /bin/sh askpass on native Windows — keep credential-in-URL
        yield f"https://x-access-token:{token}@{_HOST}/", base_env
        return
    fd, path = tempfile.mkstemp(prefix="sab-askpass-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("#!/bin/sh\n"
                    'case "$1" in\n'
                    "  Username*) printf %s 'x-access-token' ;;\n"
                    '  *) printf %s "$SAB_GH_TOKEN" ;;\n'
                    "esac\n")
        os.chmod(path, stat.S_IRWXU)  # 0700: only this user can read/exec the helper
        env = dict(base_env, GIT_ASKPASS=path, SAB_GH_TOKEN=token)
        yield f"https://x-access-token@{_HOST}/", env
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


def _run_full(repo: str | Path, args: list[str]) -> subprocess.CompletedProcess | None:
    """Run a git command in `repo`; return the CompletedProcess (None if git can't run).

    Unlike `_run`, this exposes the return code and stdout even on non-zero exit — needed
    for `merge-tree`, which exits 1 (not 0) on a conflicting auto-merge yet still prints the
    resulting tree OID.
    """
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None


def _run(repo: str | Path, args: list[str]) -> str:
    """Run a git command in `repo`; return stdout (empty string on failure)."""
    res = _run_full(repo, args)
    return res.stdout if (res is not None and res.returncode == 0) else ""


def is_git_repo(repo: str | Path) -> bool:
    return _run(repo, ["rev-parse", "--is-inside-work-tree"]).strip() == "true"


# Reachability scope for merge enumeration (G6 resolution).
#
# Chosen scope = local branches + tags + remote-tracking refs; deliberately:
#   - NOT `--all`: `--all` ALSO walks refs/stash (every `git stash` is a 2/3-parent merge
#     commit — the canonical FP), refs/notes, refs/replace and fetched forge PR refs
#     (refs/pull/*), none of which a legitimate publish surface uses; all inflate FPs/cost.
#   - WITH `--remotes`, NOT just `--branches --tags`: an evil merge can live ONLY on a
#     remote-tracking ref the user has FETCHED (refs/remotes/origin/*) without yet merging
#     it into a local branch. That object is already in the local store and is a genuine
#     local compromise; `--branches --tags` alone cannot reach it (no local branch contains
#     it) and would MISS it. `--remotes` reaches it.
#
# Why `--remotes` does NOT re-FP on unauthored origin merges: the evil-merge gate is
# CONTENT-keyed (`_corroborated`), not ref-keyed. A benign origin-only merge carries no
# worm signature / no new-vs-all-parents inject / no context-aware obfuscation, so it
# survives enumeration but produces ZERO findings. Breadth only adds *candidates*; benign
# candidates are silently discarded by the gate. (Empirically verified against benign vs
# evil remote-only merges; see tests/bots/security/test_evil_merge.py G6 cases.)
#
# Cost/dedup: `git log` deduplicates by commit SHA, so a merge reachable from both a local
# branch and a remote-tracking ref is enumerated exactly once — `--remotes` adds no
# duplicate cost in the common (local==origin) case; it only adds genuinely-extra
# remote-only commits, which is exactly the recall we want. The `_MAX_CANDIDATES` cap in
# the matcher bounds the confirm phase even on a busy upstream with many merges.
#
# One ref family per token.
_MERGE_REFS = ("--branches", "--tags", "--remotes")


def merge_commits(repo: str | Path, refs: tuple[str, ...] = _MERGE_REFS) -> list[str]:
    """SHAs of merge commits that are *candidates* for an evil merge — ALL of them,
    with no count cap (closes the G1 "merge buried behind N newer merges" miss).

    Enumeration is one git process: `git log --merges --diff-merges=first-parent
    --name-only` emits, per merge, the FIRST-PARENT diff (the change the merge brought
    onto the mainline a reviewer follows). A merge whose first-parent diff is EMPTY
    changed nothing relative to mainline (a redundant/ff-equivalent merge) and cannot
    smuggle content, so it is dropped here before any merge-tree cost is paid. Every
    other merge survives as a candidate for `evil_merge_paths` to confirm (and discard
    via the corroboration gate if benign).

    Why `--diff-merges=first-parent` and NOT `-m --first-parent`: `--first-parent`
    restricts *traversal* to the mainline chain, so an evil merge that lives INSIDE a
    merged side-branch (reachable only through a second parent) would never be
    enumerated. `--diff-merges=first-parent` sets only the per-merge DIFF FORMAT and
    leaves traversal walking every merge — closing that miss while keeping the
    first-parent (byte-identity-agnostic, see G2 below) diff. (Needs git >= 2.31; the
    precise `evil_merge_paths` path already needs >= 2.38.)

    G2 — why NOT the combined diff (`-c`): the combined diff lists only paths that
    differ from **every** parent, so it is EMPTY for an octopus that pulls in a
    payload-carrying head (the payload is byte-identical to that parent) and for a
    2-parent `-X theirs`/conflict resolution that takes one side's payload verbatim.
    Prefiltering on it silently dropped exactly those evil merges before confirmation.
    The first-parent diff is byte-identity-agnostic and keeps them.

    Cost: enumeration is one history walk; the per-candidate merge-tree confirm in
    `evil_merge_paths` then runs on the survivors. The first-parent diff is non-empty
    for nearly every real merge, so this trades the combined-diff prefilter's
    aggressive (but unsound) drop for correctness; the `_MAX_CANDIDATES` cap in the
    matcher bounds the confirm phase on pathological repositories.
    """
    out = _run(repo, ["log", "--merges", *refs, "--diff-merges=first-parent",
                      "--name-only", "--format=%x01%H"])
    candidates: list[str] = []
    cur: str | None = None
    nonempty = False
    for line in out.splitlines():
        if line.startswith("\x01"):              # record boundary: start of a new merge
            if cur and nonempty:
                candidates.append(cur)
            cur, nonempty = line[1:].strip(), False
        elif line.strip():                       # a path in this merge's first-parent diff
            nonempty = True
    if cur and nonempty:
        candidates.append(cur)
    return candidates


def parents(repo: str | Path, sha: str) -> list[str]:
    out = _run(repo, ["rev-list", "--parents", "-n", "1", sha]).split()
    return out[1:] if len(out) > 1 else []


def changed_paths(repo: str | Path, base: str, target: str,
                  diff_filter: str | None = None) -> set[str]:
    """Paths that differ between two commits/trees (name-only).

    `diff_filter` is passed straight to `git diff --diff-filter` (e.g. "AM" keeps only the
    paths `target` Adds or Modifies and drops Deletions) — callers that care about content
    `target` *introduces* want to ignore paths it merely removes.
    """
    args = ["diff", "--name-only"]
    if diff_filter:
        args.append(f"--diff-filter={diff_filter}")
    args += [base, target]
    out = _run(repo, args)
    return {line.strip() for line in out.splitlines() if line.strip()}


def _auto_merge_tree(repo: str | Path, a: str, b: str) -> str | None:
    """OID of the tree produced by a clean 3-way merge of commits `a` and `b` (their
    merge-base auto-detected). Returns the tree even when the auto-merge *conflicts* (so the
    recorded merge can be compared against the conflicted result). None when git lacks
    `merge-tree --write-tree` (pre-2.38) or the command errors.
    """
    res = _run_full(repo, ["merge-tree", "--write-tree", a, b])
    if res is None or res.returncode not in (0, 1):   # 0 = clean, 1 = conflicts; else unsupported
        return None
    oid = res.stdout.split("\n", 1)[0].strip() if res.stdout else ""
    is_oid = bool(oid) and len(oid) in (40, 64) and all(c in "0123456789abcdef" for c in oid)
    return oid if is_oid else None


def _is_generated_context(path: str) -> bool:
    """True when `path` is a vendored/minified/generated location where obfuscation is
    EXPECTED (the context-aware-confidence lever): suppress the obfuscation corroborator
    there so legitimate dense bundles never become evil-merge findings.

    Delegates to the single shared predicate in the security package so the merge
    corroborator and the whole-file obfuscation matcher use ONE source of truth and
    never drift. Imported lazily to keep core.git free of a hard security dependency."""
    from stayawake.bots.security.obfuscation import is_generated_context
    return is_generated_context(path)


def path_exists_at(repo: str | Path, treeish: str, path: str) -> bool:
    """True if `path` exists at a commit/tree (presence only — independent of whether the
    blob is text or binary). Used by the new-vs-ALL-parents corroborator so a binary file
    that decodes to '' is never mistaken for an absent file."""
    res = _run_full(repo, ["cat-file", "-e", f"{treeish}:{path}"])
    return res is not None and res.returncode == 0


def file_at(repo: str | Path, treeish: str, path: str) -> str:
    """Contents of `path` at a commit/tree (empty string if absent or binary-unreadable)."""
    res = _run_full(repo, ["cat-file", "-p", f"{treeish}:{path}"])
    if res is None or res.returncode != 0 or not res.stdout:
        return ""
    return res.stdout


def tracked(repo: str | Path, path: str) -> bool:
    """True if `path` is tracked in git — i.e. has committed history we could recover from."""
    res = _run_full(repo, ["ls-files", "--error-unmatch", "--", path])
    return res is not None and res.returncode == 0


def file_commits(repo: str | Path, path: str, limit: int = 50) -> list[str]:
    """Commit SHAs that touched `path`, newest first (bounded). The walk that the
    remediator uses to find the most recent committed version that scans clean."""
    out = _run(repo, ["log", f"-n{limit}", "--format=%H", "--", path])
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def introduced_added_text(repo: str | Path, base_tree: str, target: str, path: str) -> str:
    """The text the diff `base_tree..target` ADDS to `path` — i.e. the merge-introduced
    hunk's `+` lines, with the leading `+` stripped and diff `+++` headers excluded.

    This is the review-evading content itself: the lines present in the recorded merge
    but NOT in the clean auto-merge of its parents. We analyse exactly this delta (never
    the whole file) so a benign conflict resolution that only re-arranges existing code
    contributes nothing for the obfuscation detector to trip on."""
    out = _run(repo, ["diff", "--unified=0", "--no-color", base_tree, target, "--", path])
    added: list[str] = []
    for line in out.splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
    return "\n".join(added)


def _corroborated(repo: str | Path, base_tree: str, merge_sha: str, path: str,
                  parent_shas: list[str], content_sig=None) -> tuple[bool, str]:
    """Decide whether an introduced path is a CORROBORATED evil-merge signal, returning
    (corroborated, reason). A raw "this path deviates from the auto-merge" is NOT enough —
    benign conflict resolutions deviate too. We require one of:

      (a) NEW-vs-ALL-PARENTS — the path exists in the merge but in NONE of its parents.
          Such a file is structurally review-evading: no parent's PR diff shows it,
          regardless of its content. (Catches the classic injected-file evil merge.)
      (b) The merge-INTRODUCED hunk matches a worm content signature (loader fingerprint).
      (c) The merge-INTRODUCED hunk is OBFUSCATED relative to the file's pre-merge baseline
          (G3) — context-aware: suppressed in vendored/generated paths where obfuscation
          is expected; applied only to the introduced delta in hand-authored source.

    `content_sig` is an optional callable(text)->reason|None used for (b); kept injectable
    so this module stays free of the signature-DB import.
    """
    # (a) new vs ALL parents — content-agnostic, formatting-agnostic (presence test, so a
    #     binary file present in a parent is never misread as absent).
    if all(not path_exists_at(repo, p, path) for p in parent_shas):
        return True, "introduced file absent from every parent (review-evading)"

    # The review-evading hunk, measured against the auto-merge tree (what merging the
    # parents WOULD have produced). G2: when that auto-merge CONFLICTED at this path, the
    # conflicted tree already carries both sides' text — including a payload taken verbatim
    # from one side via `-X theirs`/manual resolution — so the auto-merge delta is empty and
    # misses it. We therefore ALSO measure the hunk against the FIRST parent (the mainline a
    # reviewer compares against): a payload resolved byte-identical to a non-first parent
    # still differs from the first parent. Corroborating on EITHER delta closes G2 without
    # re-flagging benign conflict resolutions (their first-parent hunk is ordinary code, as
    # the novel-conflict-resolution regression test asserts).
    first_parent = parent_shas[0]
    baselines = [base_tree] if base_tree == first_parent else [base_tree, first_parent]
    # (baseline, introduced-hunk) pairs with a non-empty hunk.
    pairs = [(b, introduced_added_text(repo, b, merge_sha, path)) for b in baselines]
    pairs = [(b, d) for b, d in pairs if d.strip()]
    if not pairs:
        return False, ""

    # (b) an introduced hunk matches a known worm content signature.
    if content_sig is not None:
        for _b, d in pairs:
            hit = content_sig(d)
            if hit:
                return True, f"merge-introduced hunk matches signature: {hit}"

    # (c) context-aware obfuscation of an introduced hunk (G3).
    if not _is_generated_context(path):
        # Import here to keep core.git free of a hard security-package dependency.
        from stayawake.bots.security.obfuscation import analyze_delta
        for b, d in pairs:
            verdict = analyze_delta(d, file_at(repo, b, path))
            if verdict:
                return True, f"obfuscated merge-introduced hunk: {verdict.reason}"
    return False, ""


def evil_merge_paths(repo: str | Path, merge_sha: str, content_sig=None) -> dict[str, str]:
    """Paths whose content the merge introduced BEYOND a clean 3-way merge of its parents
    AND for which that introduction is CORROBORATED as review-evading (see `_corroborated`).

    An evil merge smuggles content in the merge commit itself, where a normal PR review —
    which shows each parent's diff — can't see it. The raw signal "deviates from the clean
    auto-merge" is necessary but NOT sufficient: a legitimate conflict resolution picking a
    valid third variant of a line also deviates. So every deviating path is gated through
    `_corroborated`, which keeps the finding only when the introduction is structurally
    review-evading (new file unseen by any parent) or its INTRODUCED hunk is a worm
    signature or context-aware obfuscation. This dissolves the conflict-resolution false
    positive while still catching novel obfuscated injection (G3).

    Returns {path: reason}. Pure deletions are NOT flagged (a removed path injects nothing).
    For octopus merges (>2 parents) or when git is too old for `merge-tree --write-tree`,
    the candidate set is "added/modified vs the FIRST parent" (mainline tip) — NOT the
    intersection across every parent. The intersection silently dropped any path
    byte-identical to one parent, so an octopus payload identical to a non-first parent (G2)
    produced no finding; the first-parent diff is byte-identity-agnostic and reaches it. The
    SAME corroboration gate is then applied, so a benign octopus stays clean.
    """
    ps = parents(repo, merge_sha)
    if len(ps) < 2:
        return {}

    deviating: set[str]
    base_tree: str | None = None
    if len(ps) == 2:
        base_tree = _auto_merge_tree(repo, ps[0], ps[1])
    if base_tree is not None:
        deviating = changed_paths(repo, base_tree, merge_sha, diff_filter="AM")
    else:
        # Fallback (octopus / pre-2.38 git): we have no synthesized auto-merge tree, so the
        # FIRST parent (mainline tip) is the baseline a reviewer would compare against. The
        # candidate set is every path the merge ADDS/MODIFIES relative to that first parent
        # — i.e. everything the merge brings onto mainline.
        #
        # G2: we deliberately do NOT intersect "changed vs EVERY parent" here. That
        # intersection drops any path whose merge blob is byte-identical to even one parent
        # (an octopus that pulls a payload-carrying head, or a `-X theirs` resolution to one
        # side), so such a payload never reached the corroboration gate and produced NO
        # finding. The first-parent diff is byte-identity-agnostic: a payload identical to a
        # non-first parent still differs from the first parent and is examined. Topology
        # cannot separate evil from benign here; the `_corroborated` gate (worm signature /
        # new-vs-all-parents / context-aware obfuscation of the introduced hunk) does — so a
        # benign octopus that merely combines clean branches still yields no finding.
        base_tree = ps[0]
        deviating = changed_paths(repo, base_tree, merge_sha, diff_filter="AM")

    flagged: dict[str, str] = {}
    for path in deviating:
        ok, reason = _corroborated(repo, base_tree, merge_sha, path, ps, content_sig)
        if ok:
            flagged[path] = reason
    return flagged


def commit_meta(repo: str | Path, sha: str) -> dict[str, str]:
    out = _run(repo, ["show", "-s", "--format=%an%x09%ae%x09%cI%x09%s", sha]).strip()
    parts = out.split("\t")
    if len(parts) < 4:
        return {"sha": sha}
    return {"sha": sha, "author_name": parts[0], "author_email": parts[1],
            "date": parts[2], "subject": parts[3]}
