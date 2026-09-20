#!/usr/bin/env python3
"""`saw fix amend` — replace past commits that still carry the payload and force-update
each branch they sat on. Never `--pr`. Never moves a tag. Bare `saw fix` is unchanged.
"""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.pr.resolve import REMOVE, RESTORE, SUPPLY
from stayawake.bots.security.remediation import footprint
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.lib.git.auth import run_remote_git
from stayawake.lib.git.run import NETWORK_TIMEOUT, run, stdout_bytes
from stayawake.bots.security.pr.outcome import (AmendOutcome, BranchResult, Cause, Reason,
                                                      amended, refused, render_amend_line)
from stayawake.lib.git import authority
from stayawake.lib.git.merge import detect as mergedetect
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write import rebuild as gitrebuild
from stayawake.lib.git.write.capture import capture_bundle
from stayawake.lib.git.write.push import PushResult, force_update_head, publish_head
from stayawake.lib.git.write import sign
from stayawake.lib.git.write.replace import replacement_tree, write_blob_bytes
from stayawake.lib import git as gitutil
from stayawake.utils import env


def _full(repo: Path, sha: str) -> str:
    return gitutil.stdout(repo, ["rev-parse", "--verify", f"{sha}^{{commit}}"]).strip()


def _payload_left(repo: Path, olds, rebuilt, new_tips: dict[str, str],
                  path_checks: dict, remove=()) -> list[str]:
    """What the rebuilt objects still leave reaching the payload, checked before any reference
    moves. Empty means clean. `olds` are the pre-rewrite carrying commits; `path_checks` maps each
    corrected path to its own footprint check; `remove` maps a path to the foreign blob that must
    be gone from the tree."""
    left = []
    remove = remove or {}
    for old in sorted(olds):
        for tip in sorted(set(new_tips.values())):
            if gitutil.is_ancestor(repo, old, tip):
                left.append(f"{old[:12]} is still reachable from the rebuilt history")
    for sha in sorted(set(rebuilt.mapping.values())):
        for path in sorted(path_checks):
            if path_checks[path](sha, path):
                left.append(f"{sha[:12]} still carries {path}")
        for path in sorted(remove):
            entry = gitutil.tree_entry(repo, sha, path)
            if entry is not None and entry[1] == remove[path]:
                left.append(f"{sha[:12]} still holds {path}")
    return left


def _branches_carrying_any(repo: Path, infected) -> list[tuple[str, str, str]]:
    """Every branch that reaches ANY of the infected commits, each named once.

    A branch is rebuilt from the oldest payload it carries, so a branch reaching two of them is
    still one branch to move.
    """
    heads: dict[str, tuple[str, str, str]] = {}
    for sha in infected:
        for name, tip, cas_old in gitutil.branches_carrying(repo, sha):
            heads.setdefault(name, (name, tip, cas_old))
    return list(heads.values())


def _swept_paths(repo: Path, merge_sha: str, related, anchors) -> list[str]:
    """The paths to remove from `related`: a confirmed-payload path, or a path in a payload's
    entirely graft-introduced delivery tree. Takes the repo, the merge sha, the merge's introduced
    paths, and the confirmed-payload paths among them. Returns the subset to remove."""
    trees = {mergedetect.delivery_subtree(repo, merge_sha, a) for a in anchors}
    trees.discard(None)
    out = []
    for path in related:
        if path in anchors or any(path == d or path.startswith(d + "/") for d in trees):
            out.append(path)
    return out


def _confirmed_commits(scan) -> list:
    """Commit-carrying findings to act on, with the confirmed-payload paths in each. Takes the scan.
    Returns `(finding, anchors)` per commit that is itself confirmed, or that names a confirmed
    payload among its paths."""
    external = {getattr(f, "path", "") for f in scan.findings
                if getattr(f, "confidence", None) == CONFIRMED
                and not getattr(f, "advisory_only", False)
                and not getattr(f, "commit_sha", None)}
    found = []
    seen: set[str] = set()
    for f in scan.findings:
        related = getattr(f, "related_paths", None)
        sha = getattr(f, "commit_sha", None)
        if not related or not sha or sha in seen:
            continue
        confirmed = getattr(f, "confidence", None) == CONFIRMED
        ext = set(related) & external
        if not (confirmed or ext):
            continue
        own = set(getattr(f, "payload_paths", ()) or (related if confirmed else ()))
        anchors = tuple(sorted((own | ext) & set(related)))
        seen.add(sha)
        found.append((f, anchors))
    return found


def _flat(signatures) -> list:
    """The signature list, whether given as the by-matcher map or already flat."""
    if isinstance(signatures, dict):
        return [s for group in signatures.values() for s in group]
    return list(signatures or [])


def _content_targets(repo: Path, scan, signatures) -> list[tuple]:
    """Confirmed file findings this verb can excise, as `(finding, carries, corrector,
    cleaned_head)`, one per path and only where the corrector clears the footprint at HEAD."""
    flat = _flat(signatures)
    out = []
    seen: set[str] = set()
    for f in scan.findings:
        if getattr(f, "confidence", None) != CONFIRMED or getattr(f, "advisory_only", False):
            continue
        path = getattr(f, "path", "") or ""
        if not path or path in seen or getattr(f, "commit_sha", None):
            continue
        corrector = footprint.corrector_for(f, flat)
        carries = footprint.carries_footprint(f, flat)
        if corrector is None or carries is None:
            continue
        head = gitutil.file_at(repo, "HEAD", path)
        if not carries(head):
            continue
        cleaned = corrector(head)
        if cleaned is None or carries(cleaned):
            continue
        seen.add(path)
        out.append((f, carries, corrector, cleaned))
    return out


def _predates_content_targets(repo: Path, scan, signatures, allowlist, opts,
                              already: set[str]) -> list[tuple]:
    """Confirmed commit-finding payload paths a code-loader corrector provably clears, as
    `(path, carries, corrector)`. The corrector is derived from the path, not the finding's category,
    and proven on the flagged commit's own blob; a path it cannot clear is left out. The cleaned blob
    is then re-scanned in full, so a path whose file carries a second, co-resident payload of another
    class is left out too. `already` are the paths the HEAD content and remove lanes own."""
    flat = _flat(signatures)
    payload = _payload_matchers(signatures)
    out = []
    seen: set[str] = set()
    for finding, anchors in _confirmed_commits(scan):
        sha = getattr(finding, "commit_sha", None)
        if not sha:
            continue
        carries = footprint.carries_code_loader(flat)
        for path in anchors:
            if not path or path in already or path in seen:
                continue
            blob = gitutil.file_at(repo, sha, path)
            if not carries(blob):
                continue
            corrector = footprint.code_loader_corrector(path, flat)
            cleaned = corrector(blob)
            if cleaned is None or carries(cleaned):
                continue
            if _content_confirms(cleaned.encode("utf-8"), path, payload, allowlist, opts):
                continue
            seen.add(path)
            out.append((path, carries, corrector))
    return out


def _blast_radius(repo: Path, path: str,
                  infected: dict[str, tuple[str, ...]]) -> tuple[str, tuple[str, ...]]:
    """`(introduced_by, arrived_with_removed)` tying `path` to a confirmed injection merge that
    brought it: the merge's short id and the confirmed paths saw is removing from it. `("", ())`
    when no known injection merge brought this path; never raises."""
    for sha, payloads in infected.items():
        try:
            born = mergedetect.born_at_merge(repo, sha, (path,))
        except Exception:
            continue
        if path in born:
            return sha[:12], tuple(payloads)
    return "", ()


def _delivered_removals(replacements: dict, delivered_reach: set[str],
                        remove_holders: dict[str, set[str]],
                        purge_holders: dict[str, set[str]] | None = None) -> set[str]:
    """Paths the delivered branches actually dropped: each delivered replacement's removed paths, plus
    every whole-file or carrying-version removal whose holding commits a delivered branch reaches.
    Names only what a delivered branch removed, never a path dropped solely on an isolated branch."""
    held = dict(remove_holders)
    for path, holders in (purge_holders or {}).items():
        held[path] = held.get(path, set()) | holders
    out = {p for p, holders in held.items() if holders & delivered_reach}
    for sha, repl in replacements.items():
        if sha in delivered_reach:
            out.update(repl.removed)
    return out


def _register_removal(repo: Path, path: str, remove: dict, remove_shas: set,
                      remove_holders: dict, treeish: str = "HEAD") -> str:
    """Schedule `path` to be dropped wherever history holds the blob it has at `treeish`, recording
    the commits that hold it. Takes the repo, the path, the three removal maps to fill, and the
    treeish to key on. Returns "too-large" when the history is too long to walk, else ""."""
    entry = gitutil.tree_entry(repo, treeish, path)
    if entry is None:
        return ""
    hist = _foreign_history(repo, path, entry[1])
    if hist is None:
        return "too-large"
    _holders, foreign = hist
    if not foreign:
        return ""
    remove[path] = entry[1]
    remove_shas.update(foreign)
    remove_holders[path] = set(foreign)
    return ""


def _purge_carriers(repo: Path, path: str, survives) -> set[str] | None:
    """Walk `path`'s history and collect the commits whose version of it carries a payload. Takes the
    repo, the path, and the `survives` oracle that judges each version. Returns those commits, or None
    when the history is too long to walk."""
    changed = gitutil.file_commits(repo, path, limit=_MAX_PATH_HISTORY, all_branches=True)
    if len(changed) >= _MAX_PATH_HISTORY:
        return None
    return {sha for sha in changed if survives(sha, path)}


def _register_purge(repo: Path, path: str, purge: set, purge_shas: set, survives,
                    purge_holders: dict | None = None) -> str:
    """Schedule `path` to be dropped from every commit whose version of it carries a payload. Takes
    the repo, the path, the purge set and carrier set to fill, the `survives` oracle, and optionally a
    map recording which commits carried it. Returns "too-large" when the history is too long to walk,
    else ""."""
    carriers = _purge_carriers(repo, path, survives)
    if carriers is None:
        return "too-large"
    if not carriers:
        return ""
    purge.add(path)
    purge_shas.update(carriers)
    if purge_holders is not None:
        purge_holders[path] = set(carriers)
    return ""


def _register_operator_removal(repo: Path, path: str, remove: dict, remove_shas: set,
                               remove_holders: dict, purge: set, purge_shas: set, survives,
                               treeish: str = "HEAD", purge_holders: dict | None = None) -> str:
    """Schedule the removal an operator asked for: the version they were shown, and every other
    version of `path` that still carries a payload. Takes the repo, the path, the removal and purge
    collections to fill, the `survives` oracle, and the treeish they judged. Returns "too-large" when
    the history is too long to walk, else ""."""
    outcome = _register_removal(repo, path, remove, remove_shas, remove_holders, treeish)
    if outcome:
        return outcome
    return _register_purge(repo, path, purge, purge_shas, survives, purge_holders)


def _clean_ancestor(repo: Path, path: str, survives) -> tuple[tuple[str, str], str] | None:
    """Search `path`'s first-parent history, newest first, for the closest earlier version that
    differs from HEAD and carries no payload. Takes the repo, the path, and the `survives` oracle.
    Returns that version's tree entry with the short id of the commit it came from, or None when the
    history holds no such version."""
    head = gitutil.tree_entry(repo, "HEAD", path)
    head_oid = head[1] if head else None
    for sha in gitutil.file_commits(repo, path, limit=_MAX_PATH_HISTORY, first_parent=True):
        entry = gitutil.tree_entry(repo, sha, path)
        if entry is None or entry[1] == head_oid:
            continue
        if not survives(sha, path):
            return entry, sha[:12]
    return None


def _register_substitute(repo: Path, path: str, entry: tuple[str, str], substitute: dict,
                         substitute_shas: set, treeish: str = "HEAD") -> str:
    """Schedule `entry` to be put back wherever history holds `path` at the blob it has at `treeish`,
    recording the commits that hold it. Takes the repo, the path, the replacement tree entry, the two
    substitution maps to fill, and the treeish to key on. Returns "too-large" when the history is too
    long to walk, else ""."""
    current = gitutil.tree_entry(repo, treeish, path)
    if current is None:
        return ""
    hist = _foreign_history(repo, path, current[1])
    if hist is None:
        return "too-large"
    _holders, foreign = hist
    if not foreign:
        return ""
    substitute[path] = (current[1], entry)
    substitute_shas.update(foreign)
    return ""


def _register_supply(repo: Path, path: str, content: bytes, substitute: dict, substitute_shas: set,
                     payload, allowlist, opts) -> str:
    """Scan operator-supplied `content` and, when it carries no payload, schedule it to replace `path`
    wherever history holds the blob `path` has at HEAD. Takes the repo, the path, the content, the two
    substitution maps to fill, and the scan inputs. Returns "carries" when the content itself carries a
    payload, "unwritable" when its blob cannot be written, "too-large" when the history is too long to
    walk, else ""."""
    if _content_confirms(content, path, payload, allowlist, opts):
        return "carries"
    current = gitutil.tree_entry(repo, "HEAD", path)
    if current is None:
        return ""
    blob = write_blob_bytes(repo, content)
    if blob is None:
        return "unwritable"
    hist = _foreign_history(repo, path, current[1])
    if hist is None:
        return "too-large"
    _holders, foreign = hist
    if not foreign:
        return ""
    substitute[path] = (current[1], (current[0], blob))
    substitute_shas.update(foreign)
    return ""


def _unhandled_items(repo: Path, scan, unhandled: set[str], survives=None) -> list:
    """Build the operator's list of confirmed payloads saw could not remediate on its own, each
    offered for removal, restore, or replacement. Takes the repo, the scan, those paths, and
    optionally the `survives` oracle. Returns one `UncertainItem` per path present at HEAD, carrying
    the nearest clean version to restore when `survives` is given and one exists."""
    from stayawake.bots.security.pr.resolve import UncertainItem
    out: list = []
    seen: set[str] = set()
    for f in scan.findings:
        path = getattr(f, "path", "") or ""
        if path not in unhandled or path in seen:
            continue
        entry = gitutil.tree_entry(repo, "HEAD", path)
        if entry is None:
            continue
        seen.add(path)
        restorable = _clean_ancestor(repo, path, survives) if survives is not None else None
        out.append(UncertainItem(
            path=path, category=getattr(f, "category", "") or "",
            signature_id=getattr(f, "signature_id", "") or "",
            description=getattr(f, "description", "") or "",
            preview=stdout_bytes(repo, ["cat-file", "blob", entry[1]]) or b"",
            confirmed=True, keep_content=True,
            restore_candidate=(restorable[0] if restorable else None),
            restore_source=(restorable[1] if restorable else "")))
    return out


def _path_items(repo: Path, paths, treeish: str, introduced_by: str = "") -> list:
    """Build the operator's list for the files a commit injected, each offered for removal. Takes the
    repo, the paths, the treeish to read them from, and the short id of the merge that introduced
    them. Returns one `UncertainItem` per path present at `treeish`."""
    from stayawake.bots.security.pr.resolve import UncertainItem
    out: list = []
    for path in paths:
        entry = gitutil.tree_entry(repo, treeish, path)
        if entry is None:
            continue
        out.append(UncertainItem(
            path=path, category="evil-merge", signature_id="",
            description="injected by a merge saw could not model",
            preview=stdout_bytes(repo, ["cat-file", "blob", entry[1]]) or b"",
            introduced_by=introduced_by, confirmed=True))
    return out


def _uncertain_items(repo: Path, scan, taken: set[str],
                     infected: dict[str, tuple[str, ...]]) -> list:
    """Build the operator's list of heuristic file findings this verb would otherwise leave untouched.
    Takes the repo, the scan, the paths the confirmed lanes already own, and each injection merge
    mapped to the paths saw is removing from it, which tells the operator what a file arrived with.
    Returns one `UncertainItem` per finding whose file is present at HEAD."""
    from stayawake.bots.security.models import HEURISTIC
    from stayawake.bots.security.pr.resolve import UncertainItem
    out = []
    seen: set[str] = set()
    for f in scan.findings:
        if getattr(f, "confidence", None) != HEURISTIC or getattr(f, "advisory_only", False):
            continue
        path = getattr(f, "path", "") or ""
        if not path or path in taken or path in seen or getattr(f, "commit_sha", None):
            continue
        entry = gitutil.tree_entry(repo, "HEAD", path)
        if entry is None:
            continue
        seen.add(path)
        introduced_by, arrived = _blast_radius(repo, path, infected)
        out.append(UncertainItem(
            path=path, category=getattr(f, "category", "") or "",
            signature_id=getattr(f, "signature_id", "") or "",
            description=getattr(f, "description", "") or "",
            preview=stdout_bytes(repo, ["cat-file", "blob", entry[1]]) or b"",
            introduced_by=introduced_by, arrived_with_removed=arrived))
    return out


def _foreign_targets(scan) -> list[str]:
    """Paths of confirmed wholly-foreign files to remove whole."""
    out: list[str] = []
    for f in scan.findings:
        if getattr(f, "confidence", None) != CONFIRMED or getattr(f, "advisory_only", False):
            continue
        path = footprint.foreign_path(f)
        if path and path not in out:
            out.append(path)
    return out


def _unhandled_confirmed(scan, signatures, revert_paths: set[str],
                         cleaned_head: dict[str, str], remove_paths: set[str]) -> list[str]:
    """The paths of confirmed, non-advisory findings this verb neither reverts (a revert path),
    excises (its footprint gone from the cleaned HEAD of its path), nor removes whole. Each is a
    file the operator must recover by hand, so the caller can name them rather than count them."""
    flat = _flat(signatures)
    paths: list[str] = []
    for f in scan.findings:
        if getattr(f, "confidence", None) != CONFIRMED or getattr(f, "advisory_only", False):
            continue
        if getattr(f, "commit_sha", None) and getattr(f, "related_paths", None):
            continue
        path = getattr(f, "path", "") or ""
        if path in revert_paths or path in remove_paths:
            continue
        carries = footprint.carries_footprint(f, flat)
        if carries is not None and path in cleaned_head and not carries(cleaned_head[path]):
            continue
        if path and path not in paths:
            paths.append(path)
    return paths


_MAX_PATH_HISTORY = 100_000


def _carrying_commits(repo: Path, path: str, carries) -> list[str] | None:
    """Walk `path`'s history and collect the commits whose version of it carries the footprint.
    Takes the repo, the path, and the footprint check. Returns those commits, or None when the
    history is too long to walk."""
    changed = gitutil.file_commits(repo, path, limit=_MAX_PATH_HISTORY, all_branches=True)
    if len(changed) >= _MAX_PATH_HISTORY:
        return None
    return [sha for sha in changed if carries(gitutil.file_at(repo, sha, path))]


def _foreign_history(repo: Path, path: str, oid: str) -> tuple[list[str], list[str]] | None:
    """Walk `path`'s history and separate the commits that hold it from those holding exactly `oid`.
    Takes the repo, the path, and that blob id. Returns `(holders, holders at oid)`, or None when the
    history is too long to walk."""
    changed = gitutil.file_commits(repo, path, limit=_MAX_PATH_HISTORY, all_branches=True)
    if len(changed) >= _MAX_PATH_HISTORY:
        return None
    holders, foreign = [], []
    for sha in changed:
        entry = gitutil.tree_entry(repo, sha, path)
        if entry is None:
            continue
        holders.append(sha)
        if entry[1] == oid:
            foreign.append(sha)
    return holders, foreign


def _branches_left_carrying(repo: Path, clean: dict, covered: set[str]) -> list[str]:
    """Find the branches this run would leave behind carrying a clean-mode footprint. Takes the repo,
    the excised paths with their footprint checks, and the branch names the run already covers.
    Returns the names of the rest whose tip still carries one."""
    if not clean:
        return []
    out: set[str] = set()
    for name, ref in gitutil.branch_refs(repo):
        if name in covered:
            continue
        for path, (carries, _corrector) in clean.items():
            if carries(gitutil.file_at(repo, ref, path)):
                out.add(name)
                break
    return sorted(out)


def _branches_left_holding(repo: Path, remove: dict, covered: set[str]) -> list[str]:
    """Find the branches this run would leave behind holding a blob scheduled for removal. Takes the
    repo, each path mapped to that blob, and the branch names the run already covers. Returns the
    names of the rest whose tip still holds one."""
    if not remove:
        return []
    out: set[str] = set()
    for name, ref in gitutil.branch_refs(repo):
        if name in covered:
            continue
        for path, oid in remove.items():
            entry = gitutil.tree_entry(repo, ref, path)
            if entry is not None and entry[1] == oid:
                out.add(name)
                break
    return sorted(out)


def _branches_left_purging(repo: Path, purge: set, survives, covered: set[str]) -> list[str]:
    """Find the branches this run would leave behind carrying a purged path. Takes the repo, the
    purged paths, the `survives` oracle, and the branch names the run already covers. Returns the
    names of the rest whose tip still carries a payload at one of those paths."""
    if not purge:
        return []
    out: set[str] = set()
    for name, ref in gitutil.branch_refs(repo):
        if name in covered:
            continue
        for path in purge:
            if survives(ref, path):
                out.add(name)
                break
    return sorted(out)


_OID = set("0123456789abcdef")


def _is_oid(s: str) -> bool:
    s = (s or "").strip().lower()
    return len(s) == 40 and all(c in _OID for c in s)


def _read_remote_head(repo: Path, slug: str, branch: str,
                      token: str | None) -> tuple[bool, str | None]:
    """`(known, sha)`. `known` False means the lookup did not finish. `sha` None when
    `known` is True means the heads ref is absent."""
    res = run_remote_git(slug, token, lambda url, env: run(
        repo, ["ls-remote", "--heads", url, f"refs/heads/{branch}"], env=env,
        timeout=NETWORK_TIMEOUT))
    if res is None or res.returncode != 0:
        return False, None
    # `ls-remote <pattern>` tail-matches at `/`, so a ref named `a/refs/heads/main` answers a query
    # for `main` and sorts first — anyone who can push could choose the SHA this returns.
    wanted = f"refs/heads/{branch}"
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1].strip() != wanted:
            continue
        sha = parts[0].strip()
        return (True, sha) if _is_oid(sha) else (False, None)
    return True, None


def _collect_remote_heads(repo: Path, slug: str, names: list[str],
                          token: str | None) -> tuple[dict[str, str | None] | None, str | None]:
    """Each branch's remote SHA (`None` if absent). `(None, name)` when `name` could not be read."""
    found: dict[str, str | None] = {}
    for name in names:
        known, sha = _read_remote_head(repo, slug, name, token)
        if not known:
            return None, name
        found[name] = sha
    return found, None


def _destination(slug: str, branch: str, token: str | None,
                 sha12: str) -> tuple[str, Reason | None]:
    """Where this branch's amended history goes, as `(branch, reason)`."""
    protection = authority.ref_protection(slug, branch, token)
    if protection.protected is False:
        return branch, None
    cause = Cause.BRANCH_PROTECTED if protection.protected else Cause.PROTECTION_UNKNOWN
    aside = f"security/amend-{sha12}"
    return aside, Reason(cause, aside)


def _push_to(repo: Path, slug: str, branch: str, dest: str, token: str | None,
             lease: str | None, pusher, *, force: bool) -> PushResult:
    """The transport, and the only part a caller may substitute.

    `force` is passed in rather than re-derived from `dest != branch`: a branch named exactly like
    the aside ref makes those two names equal, and the transport would then force-update the very
    ref the destination decision had just protected.
    """
    if pusher is not None:
        return pusher(branch, dest, lease)
    if not force or lease is None:
        return publish_head(repo, slug, branch, token, dest=dest)
    return force_update_head(repo, slug, branch, token, lease=lease)


def _force_update_branch(repo: Path, slug: str, branch: str, token: str | None, *,
                         pusher, lease: str | None = None,
                         sha12: str = "") -> BranchResult:
    dest, aside = _destination(slug, branch, token, sha12)
    result = _push_to(repo, slug, branch, dest, token, lease, pusher,
                      force=aside is None)
    if aside is not None:
        return BranchResult(branch, False,
                            aside if result.ok else Reason(Cause.PUSH_REFUSED, branch))
    if not result.ok:
        return BranchResult(branch, False, Reason(Cause.PUSH_REFUSED, branch))
    if pusher is not None:
        return BranchResult(branch, True)
    known, remote = _read_remote_head(repo, slug, branch, token)
    local = gitutil.stdout(repo, ["rev-parse", f"refs/heads/{branch}"]).strip()
    if known and remote and local and remote == local:
        return BranchResult(branch, True)
    if not known:
        # An accepted push whose result cannot be read back is not a refusal. Calling it one used
        # to send the local branch back to the payload tip, which GUARANTEES the divergence the
        # restore was meant to avoid: the remote most likely holds the replacement.
        return BranchResult(branch, False, Reason(Cause.PUSH_NOT_CONFIRMED, branch))
    return BranchResult(branch, False, Reason(Cause.REMOTE_DID_NOT_MOVE, branch))


def _capture_path(slug: str, sha12: str) -> Path:
    """Where the objects the replacement orphans are captured before any ref moves.

    Outside the repository entirely. Inside the worktree a new file makes the tree dirty and the
    ref move is then refused; inside the git directory the capture dies with the checkout, and on
    `--remote` that checkout is a temporary clone deleted seconds after the remote refs move — so
    the evidence had a shorter life than the destruction it authorised. Cross-run state is the one
    place that outlives both.
    """
    safe = "".join(c if c.isalnum() or c in "-._" else "-" for c in slug) or "repository"
    return Path(env.xdg_state_home()) / "saw" / "amend" / safe / sha12 / "capture.bundle"


_CAUSE_PER_REFUSAL_KIND = {
    "conflicted": Cause.MERGE_WOULD_NOT_RESOLVE,
    "shape": Cause.COMMIT_SHAPE_NOT_MODELLED,
    "submodule": Cause.PAYLOAD_IN_A_SUBMODULE,
    "unnamed": Cause.COMMIT_SHAPE_NOT_MODELLED,
    "not-applied": Cause.REPLACEMENT_DID_NOT_APPLY,
    "headers": Cause.COMMIT_RECORDS_MORE_THAN_A_REPLACEMENT_CARRIES,
    "message-encoding": Cause.COMMIT_RECORDS_MORE_THAN_A_REPLACEMENT_CARRIES,
    "message": Cause.REPLACEMENT_NOT_WRITTEN,
    "baseline-carries-payload": Cause.PAYLOAD_PREDATES_THIS_COMMIT,
    "changed-downstream": Cause.PAYLOAD_CHANGED_AFTER_THIS_COMMIT,
    "replacement-loses-more": Cause.REPLACEMENT_LOSES_MORE_THAN_THE_PAYLOAD,
}


def _payload_matchers(signatures):
    """The by-matcher signatures minus the groups that need the repo, history, or install state —
    the matchers that judge a single file's own content."""
    return ({k: v for k, v in signatures.items()
             if k not in ("git-history", "dependency-audit", "installed-package-audit")}
            if isinstance(signatures, dict) else signatures)


def _content_confirms(content: bytes, path: str, payload, allowlist, opts,
                      is_symlink: bool = False) -> str | None:
    """The confirmed signature id `content` triggers when scanned as `path`, or None. A truthy
    result — a signature id or an errored token — means treat the content as unclean."""
    import os
    import shutil
    import tempfile
    from stayawake.bots.security import scanner as _scanner
    from stayawake.bots.security.targets.base import Target
    tmp = tempfile.mkdtemp(prefix="saw-amend-oracle-")
    try:
        dest = os.path.join(tmp, path)
        os.makedirs(os.path.dirname(dest) or tmp, exist_ok=True)
        if is_symlink:
            os.symlink(os.fsdecode(content), dest)
        else:
            with open(dest, "wb") as handle:
                handle.write(content)
        target = Target(tmp, tmp, opts, include_only=(path,))
        target.names_one_file = True
        target.is_repo = False
        result = _scanner.scan_target(target, payload, allowlist)
    except (OSError, ValueError):
        return "materialize-error"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if result.error is not None:
        return "scan-error"
    return next((getattr(f, "signature_id", "confirmed") for f in result.findings
                 if getattr(f, "path", "") == path
                 and getattr(f, "confidence", None) == CONFIRMED
                 and not getattr(f, "advisory_only", False)), None)


def _survives(repo, signatures, allowlist, opts) -> object:
    """`check(treeish, path) -> str | None` for whether a path's content in a tree confirms a payload.
    Takes the repo, the by-matcher signatures, the allowlist, and the scan options. Returns the check;
    a truthy result — a signature id, or an unreadable/errored token — means treat the path as unclean."""
    payload = _payload_matchers(signatures)
    scanned: dict[tuple, str | None] = {}

    def check(treeish, path):
        entry = gitutil.tree_entry(repo, treeish, path)
        if entry is None:
            return None
        sha = entry[1]
        if (path, sha) not in scanned:
            blob = stdout_bytes(repo, ["cat-file", "blob", sha])
            if blob is None:
                scanned[(path, sha)] = "read-error"
            else:
                scanned[(path, sha)] = _content_confirms(blob, path, payload, allowlist, opts,
                                                         is_symlink=(entry[0] == "120000"))
        return scanned[(path, sha)]

    return check


def _tags_at(repo: Path, slug: str, olds: list[str], token: str | None) -> tuple[list[str], bool]:
    """Tag names still pointing at the replaced commit, and whether that could be established.

    Asked of the REMOTE, not of this clone. The refresh this run does is `--no-tags`, so a tag
    pushed since the operator last fetched is invisible here — and one `clone --branch <tag>` puts
    the payload back on disk. `ls-remote --tags` reports both the tag object and its peeled `^{}`
    line, so an annotated tag is matched by the commit it resolves to.
    """
    local = [name for sha in olds
             for name in gitutil.stdout(repo, ["tag", "--points-at", sha]).split()]
    res = run_remote_git(slug, token, lambda url, env: run(
        repo, ["ls-remote", "--tags", url], env=env, timeout=NETWORK_TIMEOUT))
    if res is None or res.returncode != 0:
        return sorted(set(local)), False
    remote = []
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].strip() in set(olds) and parts[1].startswith("refs/tags/"):
            remote.append(parts[1][len("refs/tags/"):].removesuffix("^{}"))
    return sorted(set(local) | set(remote)), True


def _survivors(repo: Path, slug: str, olds: list[str], token: str | None) -> list[Reason]:
    """What the force-update leaves reachable. Each one makes the run need review.

    Forks are counted rather than assumed. Reporting "forks were not established" on every run
    made `needs_review` True for every outcome the module could produce, refused and completed
    alike — a flag that fires every time carries no information and hides the runs that really do
    need a person.
    """
    reasons = [Reason(Cause.PREVIOUS_OBJECTS_UNCOLLECTED)]
    tags, established = _tags_at(repo, slug, olds, token)
    if tags:
        reasons.append(Reason(Cause.TAGS_AT_REPLACED_COMMIT, ", ".join(sorted(tags))))
    elif not established:
        reasons.append(Reason(Cause.TAGS_NOT_ESTABLISHED))
    forks = authority.fork_count(slug, token)
    if forks is None:
        reasons.append(Reason(Cause.FORKS_NOT_ESTABLISHED))
    elif forks:
        reasons.append(Reason(Cause.FORKS_EXIST, str(forks)))
    return reasons


def amend_repo(repo: Path, opts, signatures, allowlist, token: str | None = None, *,
               pusher=None,
               identity_fallback: str | None = None,
               operator_context: Path | None = None, resolver=None) -> str:
    """Force-update every branch that still reaches a confirmed past-commit payload.

    The local rewrite is a step. The result is the remote refs moving. Returns one operator line.
    A confirmed wholly-foreign file is removed from history too. `resolver`, when given, is asked to
    keep or remove each heuristic file the verb would otherwise leave.
    """
    display = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    outcome = amend_outcome(repo, display, opts, signatures, allowlist, token, pusher=pusher,
                            identity_fallback=identity_fallback,
                            operator_context=operator_context, resolver=resolver)
    return render_amend_line(outcome)


def amend_outcome(repo: Path, display: str, opts, signatures, allowlist, token, *,
                  pusher=None,
                  identity_fallback: str | None = None,
                  operator_context: Path | None = None, resolver=None) -> AmendOutcome:
    """The act, as a structure. Prose is rendered from this and never parsed back out of it.

    `operator_context` is where the operator's own git config lives (signer, identity); it defaults
    to `repo`. `identity_fallback` is the operator's session credential for the authority gate. Both
    pass straight through to the gates.
    """
    if not gitutil.is_git_repo(repo):
        return refused(display, Cause.NOT_A_GIT_REPOSITORY)
    if gitamend.is_dirty(repo):
        return refused(display, Cause.WORKING_TREE_NOT_CLEAN)

    slug = gitutil.origin_slug(repo)
    if not slug:
        return refused(display, Cause.NO_REMOTE)
    if not (token or "").strip() and pusher is None:
        return refused(display, Cause.NO_CREDENTIAL)

    permitted = authority.may_rewrite(slug, token, identity_fallback=identity_fallback)
    if not permitted.permitted:
        return refused(display, Cause.NOT_PERMITTED_TO_REWRITE,
                       permitted.detail or permitted.reason)
    fetched = gitutil.fetch_refs(repo, token=token)
    if not fetched.ok:
        return refused(display, Cause.REMOTE_REFS_UNREADABLE, fetched.reason)

    scan = scan_target(LocalRepoTarget(repo, str(repo), opts), signatures, allowlist)
    if scan.error is not None:
        return refused(display, Cause.SCAN_DID_NOT_FINISH)
    commits = _confirmed_commits(scan)
    infected: dict[str, tuple[str, ...]] = {}
    uncharacterized: dict[str, tuple[str, str]] = {}
    uncharacterized_paths: dict[str, tuple[str, ...]] = {}
    for finding, anchors in commits:
        reported = getattr(finding, "commit_sha", None) or ""
        sha = _full(repo, reported)
        if not sha:
            named = ", ".join(getattr(finding, "related_paths", ()) or ())
            return refused(display, Cause.CONFIRMED_COMMIT_UNRESOLVED,
                           f"{reported[:12]}: {named}" if named else (reported[:12] or "?"))
        related = tuple(getattr(finding, "related_paths", ()) or ())
        paths = tuple(_swept_paths(repo, sha, related, anchors))
        if not paths:
            uncharacterized[sha] = ("shape", sha[:12])
            uncharacterized_paths[sha] = tuple(sorted(mergedetect.born_at_merge(repo, sha, related)))
            continue
        infected[sha] = tuple(dict.fromkeys(infected.get(sha, ()) + paths))

    clean: dict[str, tuple] = {}
    clean_shas: set[str] = set()
    cleaned_head: dict[str, str] = {}
    for finding, carries, corrector, head_clean in _content_targets(repo, scan, signatures):
        carrying = _carrying_commits(repo, finding.path, carries)
        if carrying is None:
            return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, finding.path)
        if not carrying:
            return refused(display, Cause.CONFIRMED_COMMIT_UNRESOLVED, finding.path)
        clean[finding.path] = (carries, corrector)
        clean_shas.update(carrying)
        cleaned_head[finding.path] = head_clean

    for path, carries, corrector in _predates_content_targets(
            repo, scan, signatures, allowlist, opts, set(clean)):
        carrying = _carrying_commits(repo, path, carries)
        if carrying is None:
            return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, path)
        if not carrying:
            continue
        clean[path] = (carries, corrector)
        clean_shas.update(carrying)

    remove: dict[str, str] = {}
    remove_shas: set[str] = set()
    remove_holders: dict[str, set[str]] = {}
    for path in _foreign_targets(scan):
        if path in clean or path in {p for ps in infected.values() for p in ps}:
            continue
        entry = gitutil.tree_entry(repo, "HEAD", path)
        if entry is None:
            continue
        hist = _foreign_history(repo, path, entry[1])
        if hist is None:
            return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, path)
        holders, foreign = hist
        if not foreign or set(holders) != set(foreign):
            continue
        remove[path] = entry[1]
        remove_shas.update(foreign)
        remove_holders[path] = set(foreign)

    survives = _survives(repo, signatures, allowlist, opts)
    substitute: dict[str, tuple[str, tuple[str, str]]] = {}
    substitute_shas: set[str] = set()
    supply_paths: set[str] = set()
    purge: set[str] = set()
    purge_shas: set[str] = set()
    purge_holders: dict[str, set[str]] = {}

    if resolver is not None:
        held = set(clean) | set(remove) | {p for ps in infected.values() for p in ps}
        for item in _uncertain_items(repo, scan, held, infected):
            try:
                answer = resolver(item)
            except Exception:                  # a resolver fault leaves the file for review
                continue
            if answer.action == REMOVE and _register_operator_removal(
                    repo, item.path, remove, remove_shas, remove_holders,
                    purge, purge_shas, survives,
                    purge_holders=purge_holders) == "too-large":
                return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)

    infected = {sha: tuple(p for p in ps if p not in clean and p not in remove)
                for sha, ps in infected.items()}
    infected = {sha: ps for sha, ps in infected.items() if ps}
    taken = {p for ps in infected.values() for p in ps}

    unhandled = _unhandled_confirmed(scan, signatures, taken, cleaned_head, remove)
    if resolver is not None and unhandled:
        for item in _unhandled_items(repo, scan, unhandled, survives):
            try:
                answer = resolver(item)
            except Exception:
                continue
            if answer.action == RESTORE and answer.restore is not None:
                if _register_substitute(repo, item.path, answer.restore,
                                        substitute, substitute_shas) == "too-large":
                    return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
            elif answer.action == SUPPLY and isinstance(answer.supply, bytes):
                if _register_supply(repo, item.path, answer.supply, substitute, substitute_shas,
                                    _payload_matchers(signatures), allowlist, opts) == "too-large":
                    return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
                if item.path in substitute:
                    supply_paths.add(item.path)
            elif answer.action == REMOVE and _register_operator_removal(
                    repo, item.path, remove, remove_shas, remove_holders,
                    purge, purge_shas, survives,
                    purge_holders=purge_holders) == "too-large":
                return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
        unhandled = _unhandled_confirmed(scan, signatures, taken, cleaned_head,
                                         set(remove) | set(substitute) | set(purge))
    if resolver is not None and uncharacterized:
        for sha in list(uncharacterized):
            present = [p for p in uncharacterized_paths.get(sha, ())
                       if gitutil.tree_entry(repo, sha, p) is not None]
            if not present:
                continue
            for item in _path_items(repo, present, sha, sha[:12]):
                try:
                    answer = resolver(item)
                except Exception:
                    continue
                if answer.action == REMOVE and _register_operator_removal(
                        repo, item.path, remove, remove_shas, remove_holders,
                        purge, purge_shas, survives, sha, purge_holders) == "too-large":
                    return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)
            if all(p in remove for p in present):
                del uncharacterized[sha]

    blocked_infected: dict[str, tuple[str, str]] = {}
    for sha in list(infected):
        rep = replacement_tree(repo, sha, infected[sha], survives)
        if not rep.ok:
            blocked_infected[sha] = (rep.kind or "replacement", rep.refusal or sha[:12])
    if resolver is not None and blocked_infected:
        for sha in blocked_infected:
            present = [p for p in infected[sha] if gitutil.tree_entry(repo, sha, p) is not None]
            for item in _path_items(repo, present, sha, sha[:12]):
                try:
                    answer = resolver(item)
                except Exception:
                    continue
                if answer.action == REMOVE and _register_purge(
                        repo, item.path, purge, purge_shas, survives) == "too-large":
                    return refused(display, Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, item.path)

    if not infected and not clean and not remove and not substitute and not purge:
        if unhandled:
            return refused(display, Cause.PAYLOAD_NEEDS_MANUAL_RECOVERY,
                           str(len(unhandled)), ", ".join(sorted(unhandled)))
        return refused(display, Cause.NO_CONFIRMED_PAYLOAD)

    all_infected = (set(infected) | clean_shas | remove_shas | substitute_shas | purge_shas
                    | set(uncharacterized))
    heads = _branches_carrying_any(repo, all_infected)
    if not heads:
        return refused(display, Cause.COMMIT_ON_NO_BRANCH,
                       ", ".join(sorted(s[:12] for s in all_infected)))
    covered = {n for n, _t, _c in heads}
    off_plan = _branches_left_carrying(repo, clean, covered) + \
        _branches_left_holding(repo, remove, covered) + \
        _branches_left_holding(repo, {p: fo for p, (fo, _e) in substitute.items()}, covered) + \
        _branches_left_purging(repo, purge, survives, covered)
    if off_plan:
        return refused(display, Cause.PAYLOAD_STILL_REACHABLE, ", ".join(sorted(set(off_plan))))

    graph = gitrebuild.ordered_graph(repo, [tip for _n, tip, _c in heads])
    plan = gitrebuild.commits_to_rebuild(graph, all_infected)
    uncovered = sorted(s for s in all_infected if s not in {sha for sha, _ps in plan})
    if uncovered:
        # A confirmed commit no branch reaches is not amendable here, and counting it as replaced
        # would report commits the run never touched.
        return refused(display, Cause.COMMIT_ON_NO_BRANCH,
                       ", ".join(s[:12] for s in uncovered))
    oldest = plan[0][0]

    # Two sources: whether a signature is owed is read from the commits being replaced (`repo`);
    # the signer that produces it is read from the operator's own config context. `operator_context`
    # is not a context saw named, so its program keys are not trusted (see `signing_status`).
    signing = sign.signing_status(
        operator_context or repo,
        history_is_signed=sign.any_signed(repo, [sha for sha, _ps in plan]),
        trust_local_programs=operator_context is None)
    if signing.must_refuse:
        return refused(display, Cause.SIGNING_UNAVAILABLE, signing.reason)
    if sign.committer_identity(repo) is None:
        return refused(display, Cause.NO_COMMITTER_IDENTITY)

    leases, unread = _collect_remote_heads(repo, slug, [n for n, _, _ in heads], token)
    if unread is not None:
        return refused(display, Cause.REMOTE_BRANCH_UNREADABLE, unread)
    behind = sorted(name for name, tip, _cas in heads
                    if leases.get(name) and not gitutil.is_ancestor(repo, leases[name], tip))
    if behind:
        return refused(display, Cause.LOCAL_MISSING_REMOTE_COMMITS, ", ".join(behind))

    replacements = {}
    blocked_commits: dict[str, tuple[str, str]] = dict(uncharacterized)
    recovered_paths: set[str] = set()
    for sha, paths in infected.items():
        if all(p in purge for p in paths):
            continue
        replacement = gitamend.replacement_commit(repo, sha, paths, signing, survives)
        if not replacement.ok:
            blocked_commits[sha] = (replacement.kind or "replacement",
                                    replacement.refusal or sha[:12])
            continue
        beyond = [p for p in gitamend.discarded_delta(repo, sha, replacement.sha)
                  if p not in paths]
        if beyond:
            blocked_commits[sha] = ("replacement-loses-more", ", ".join(sorted(beyond)[:5]))
            continue
        recovered_paths |= set(replacement.recovered)
        replacements[sha] = replacement

    # Objects only — no reference moves until the capture below has been read back.
    rebuilt = gitrebuild.rebuild_without_payload(
        repo, plan, replacements,
        lambda sha, tree, new_parents: gitamend.rewrite_commit(repo, sha, tree, new_parents,
                                                               signing),
        survives, clean=clean, remove=remove, pre_blocked=blocked_commits,
        substitute=substitute, purge=purge)
    blocked = rebuilt.blocked

    new_tips = {tip: rebuilt.tip(tip) for _n, tip, _c in heads}
    flagged = ({p for paths in infected.values() for p in paths}
               | set(clean) | set(remove) | set(substitute) | set(purge))

    deliverable: list[tuple[str, str, str]] = []
    isolated: list[BranchResult] = []
    for name, tip, cas in heads:
        if tip in blocked:
            kind, refusal = blocked[tip]
            isolated.append(BranchResult(name, False, Reason(
                _CAUSE_PER_REFUSAL_KIND.get(kind, Cause.REPLACEMENT_NOT_WRITTEN), refusal)))
            continue
        beyond = [p for p in gitamend.discarded_delta(repo, tip, new_tips[tip])
                  if p not in flagged]
        if beyond:
            isolated.append(BranchResult(name, False, Reason(
                Cause.REPLAY_CHANGED_UNRELATED_COMMITS,
                f"{name}: " + ", ".join(sorted(beyond)[:3]))))
            continue
        deliverable.append((name, tip, cas))

    if not deliverable:
        reason = isolated[0].reason if isolated else Reason(Cause.PAYLOAD_STILL_REACHABLE)
        return refused(display, reason.cause, reason.detail, reason.subjects)

    delivered_tips = {tip: new_tips[tip] for _n, tip, _c in deliverable}
    # Count and name only commits a delivered branch reaches, not ones rebuilt for an isolated one.
    reachable = gitutil.stdout(repo, ["rev-list", *[t for _n, t, _c in deliverable]]).split()
    delivered_reach = set(reachable)
    oldest = next((sha for sha, _ps in plan
                   if sha in rebuilt.mapping and sha in delivered_reach), oldest)
    delivered_infected = [s for s in all_infected if s in rebuilt.mapping and s in delivered_reach]

    path_checks = {p: survives for p in flagged}
    path_checks.update({p: (lambda tr, pth, c=carries: c(gitutil.file_at(repo, tr, pth)))
                        for p, (carries, _c) in clean.items()})
    left = _payload_left(repo, all_infected, rebuilt, delivered_tips, path_checks, remove)
    if left:
        return refused(display, Cause.PAYLOAD_STILL_REACHABLE, "; ".join(left[:3]))

    captured = capture_bundle(repo, [(tip, new_tips[tip]) for _n, tip, _c in deliverable],
                              _capture_path(slug, oldest[:12]))
    if not captured.ok:
        return refused(display, Cause.CAPTURE_FAILED, captured.reason)

    try:
        moved = gitamend.point_branches(repo, deliverable, delivered_tips)
    except gitamend.AmendUnwindFailed as unwound:
        return refused(display, Cause.LEFT_PART_WAY, ", ".join(unwound.unrestored),
                       recovery=str(captured.path or ""))
    if moved is None:
        return refused(display, Cause.REPLAY_FAILED, ", ".join(n for n, _, _ in deliverable))

    results: list[BranchResult] = []
    failed: list[str] = []
    for branch in moved:
        result = _force_update_branch(repo, slug, branch, token, pusher=pusher,
                                      lease=(leases or {}).get(branch),
                                      sha12=oldest[:12])
        results.append(result)
        cause = result.reason.cause if result.reason is not None else None
        if not result.force_updated and cause is not Cause.PUSH_NOT_CONFIRMED:
            failed.append(branch)
    survivors = _survivors(repo, slug, sorted(delivered_infected), token)
    delivered_sub = [p for p in substitute
                     if any(gitutil.tree_entry(repo, t, p) is not None
                            for t in delivered_tips.values())]
    supplied = sorted(p for p in delivered_sub if p in supply_paths)
    restored = sorted(p for p in delivered_sub if p not in supply_paths)
    if supplied:
        survivors.insert(0, Reason(Cause.FILE_REPLACED_WITH_SUPPLIED_CONTENT, ", ".join(supplied)))
    if restored:
        survivors.insert(0, Reason(Cause.FILE_RESTORED_TO_A_CLEAN_VERSION, ", ".join(restored)))
    if recovered_paths:
        survivors.insert(0, Reason(Cause.FILE_RESTORED_FROM_A_PARENT,
                                   ", ".join(sorted(recovered_paths))))
    if unhandled:
        survivors.insert(0, Reason(Cause.PAYLOAD_NEEDS_MANUAL_RECOVERY,
                                   str(len(unhandled)), ", ".join(sorted(unhandled))))
    recovery = ""
    if failed:
        try:
            unrestored = gitamend.restore_branches(repo, deliverable, moved, failed)
        except gitamend.AmendUnwindFailed as unwound:
            unrestored = unwound.unrestored
        if unrestored:
            # The pre-push caller already reports this; reporting it here too is the point — the
            # same refused restore was silent on this side, and a local branch left on rewritten
            # history is the operator's problem whether or not any push succeeded.
            survivors.insert(0, Reason(Cause.LEFT_PART_WAY, ", ".join(unrestored)))
            recovery = str(captured.path or "")
    removed = _delivered_removals(replacements, delivered_reach, remove_holders, purge_holders)
    touched = len(delivered_infected)
    label = (oldest[:12] if touched == 1 else f"{touched} commits from {oldest[:12]}")
    return amended(display, label, tuple(results) + tuple(isolated), tuple(survivors),
                   sorted(removed), recovery=recovery)
