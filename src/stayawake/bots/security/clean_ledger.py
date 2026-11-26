#!/usr/bin/env python3
"""saw's record of which repository trees it checked clean, by repository and policy.

The scan-on-clone hooks and `saw govern` both write here. A tree saw checked clean — by a hook after
a clone or a pull, or by govern before it let an update into the open folder — is remembered by its
commit and the policy it was judged under. A change that reached the working tree outside saw's
check is then the one this record does not know.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from stayawake.bots.security import hookscript, push_record
from stayawake.bots.security.hook_policy import operator_policy
from stayawake.lib.git.inside_a_repository import lies_inside_a_repository
from stayawake.utils import atomicwrite

cache_path = hookscript.cache_path


def _kept_outside_every_repository() -> bool:
    """Tell whether the folder holding saw's record lies outside every git repository. Returns the
    answer."""
    return not lies_inside_a_repository(cache_path().parent)


def load_cache() -> dict:
    if not _kept_outside_every_repository():
        return {}
    try:
        cache = json.loads(cache_path().read_text())
    except (OSError, ValueError):
        return {}
    return cache if isinstance(cache, dict) else {}


def policy_digest(config_path: str | None) -> str:
    """Name the policy a scan judges under. Takes the operator config. Returns the digest of its
    signatures, allowlist, file size limit and the folders a walk of the tree reads or skips."""
    policy = operator_policy(config_path)
    opts = policy.opts
    digest = push_record.policy_digest(policy.signatures, policy.allowlist,
                                       getattr(opts, "max_file_bytes", 0))
    walked = json.dumps([sorted(getattr(opts, "exclude_dirs", ())), sorted(getattr(opts, "keep_dirs", ())),
                         bool(getattr(opts, "scan_build_outputs", False))])
    return f"{digest}:{hashlib.sha256(walked.encode()).hexdigest()}"


def clean_key(head: str, config_path: str | None) -> str:
    """Name a complete clean scan of a repository's tree. Takes the commit and the operator config.
    Returns the commit joined to the digest of the policy it was judged under."""
    return f"{head}:{policy_digest(config_path)}"


def settings_scans() -> dict:
    """Read the clean scans a run from git's settings remembers. Returns them by repository, none
    when the record lies inside a git repository."""
    if not _kept_outside_every_repository():
        return {}
    try:
        held = json.loads(hookscript.settings_scan_path().read_text())
    except (OSError, ValueError):
        return {}
    return held if isinstance(held, dict) else {}


def remember_settings_scan(root: Path, key: str) -> None:
    """Remember a clean scan a run from git's settings made, apart from saw's list of repositories it
    keeps current. Takes the root and the clean key. A write that fails, or one into a record inside a
    git repository, is skipped."""
    if not _kept_outside_every_repository():
        return
    held = {r: k for r, k in settings_scans().items() if os.path.isdir(r)}
    held[os.path.realpath(root)] = key
    atomicwrite.replace(hookscript.settings_scan_path(), json.dumps(held))


def remember(root: Path, key: str) -> None:
    """Record a scanned repository, and the clean scan it may skip next time. Takes the root and
    the clean key, or "" when the scan was not clean. A write that fails, or one into a record inside
    a git repository, is skipped."""
    if not _kept_outside_every_repository():
        return
    try:
        cache = {r: s for r, s in load_cache().items() if os.path.isdir(r)}
        cache[os.path.realpath(root)] = key
        atomicwrite.replace(cache_path(), json.dumps(cache), mode=atomicwrite.AS_A_PLAIN_WRITE, at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK)
    except OSError:
        pass


def scanned_clean(root: Path, key: str) -> bool:
    """Tell whether saw remembers a complete clean scan of a repository. Takes the root and the clean
    key. Returns the answer."""
    return key in (load_cache().get(os.path.realpath(root)), settings_scans().get(os.path.realpath(root)))


def applied_path() -> Path:
    """The record of trees `saw govern` applied — clean or residue — kept apart from the
    strictly-clean scan cache, so a residue apply counts as governed without widening the hook skip."""
    return cache_path().with_name("govern-applied.json")


def _load_record(path: Path) -> dict:
    """Read a govern record kept outside every git repository. Takes its path. Returns it by
    repository, or an empty one."""
    if not _kept_outside_every_repository():
        return {}
    try:
        held = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return held if isinstance(held, dict) else {}


def load_applied() -> dict:
    return _load_record(applied_path())


def remember_applied(root: Path, key: str) -> None:
    """Record a tree govern let into a repository, clean or residue. Takes the root and the key.
    A write that fails, or one into a record inside a git repository, is skipped."""
    if not _kept_outside_every_repository():
        return
    try:
        held = {r: k for r, k in load_applied().items() if os.path.isdir(r)}
        held[os.path.realpath(root)] = key
        atomicwrite.replace(applied_path(), json.dumps(held), mode=atomicwrite.AS_A_PLAIN_WRITE,
                            at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK)
    except OSError:
        pass


def is_applied(root: Path, key: str) -> bool:
    """Tell whether govern let this exact tree into a repository, clean or residue. Takes the root
    and the key. Returns the answer."""
    return load_applied().get(os.path.realpath(root)) == key


def let_in_commit(root: Path, config_path: str | None) -> str | None:
    """The commit saw last let into a repository under the current policy — applied by govern, or
    scanned clean by a hook — or None. Takes the root and the operator config. Returns the commit."""
    import os as _os
    want = policy_digest(config_path)
    for store in (load_applied(), load_cache(), settings_scans()):
        key = store.get(_os.path.realpath(root))
        if isinstance(key, str):
            commit, sep, rest = key.partition(":")
            if sep and rest == want and commit:
                return commit
    return None


def governed(root: Path, key: str) -> bool:
    """Tell whether saw vouches for this tree — scanned clean by a hook, or let in by govern (clean
    or residue). Takes the root and the key. Returns the answer."""
    return scanned_clean(root, key) or is_applied(root, key)


def accepted_path() -> Path:
    """The record of trees the user let in although saw found them suspicious or infected."""
    return cache_path().with_name("govern-accepted.json")


def remember_accepted(root: Path, commit: str, verdict: str) -> None:
    """Record that the user let a held tree into a repository. Takes the root, the commit and the
    verdict saw gave it. A write that fails, or one into a record inside a git repository, is
    skipped."""
    if not _kept_outside_every_repository():
        return
    try:
        held = {r: v for r, v in _load_record(accepted_path()).items() if os.path.isdir(r)}
        held[os.path.realpath(root)] = {"commit": commit, "verdict": verdict}
        atomicwrite.replace(accepted_path(), json.dumps(held), mode=atomicwrite.AS_A_PLAIN_WRITE,
                            at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK)
    except OSError:
        pass


def accepted_verdict(root: Path, commit: str) -> str | None:
    """Return the verdict of a held tree the user let into a repository, when it is this commit.
    Takes the root and the commit."""
    entry = _load_record(accepted_path()).get(os.path.realpath(root))
    if isinstance(entry, dict) and entry.get("commit") == commit and isinstance(entry.get("verdict"), str):
        return entry["verdict"]
    return None


_MOST_LET_IN_BLOBS = 50000


def let_in_blobs_path() -> Path:
    """The record of file contents `saw govern` let into a repository, by path, mode and blob id."""
    return cache_path().with_name("govern-let-in-blobs.json")


def remember_blobs(root: Path, contents: list, policy: str) -> None:
    """Record the contents govern let into a repository, under the policy they were judged by.
    Takes the root, each content as (path, mode, blob id), and the digest of the policy. A write
    that fails, or one into a record inside a git repository, is skipped."""
    if not contents or not policy or not _kept_outside_every_repository():
        return
    try:
        held = {r: k for r, k in _load_record(let_in_blobs_path()).items() if os.path.isdir(r) and isinstance(k, dict)}
        kept = held.get(os.path.realpath(root), {})
        entries = [entry for entry in (kept.get("blobs") or []) if _is_content(entry)] \
            if kept.get("policy") == policy else []
        known = {tuple(entry) for entry in entries}
        entries += [list(content) for content in sorted(tuple(content) for content in contents if _is_content(content))
                    if content not in known]
        held[os.path.realpath(root)] = {"policy": policy, "blobs": entries[-_MOST_LET_IN_BLOBS:]}
        atomicwrite.replace(let_in_blobs_path(), json.dumps(held), mode=atomicwrite.AS_A_PLAIN_WRITE,
                            at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK)
    except OSError:
        pass


def blobs_let_in(root: Path, config_path: str | None) -> set[tuple[str, str, str]]:
    """Read the contents govern let into a repository under the current policy. Takes the root and
    the operator config. Returns each (path, mode, blob id), none after a change of policy."""
    kept = _load_record(let_in_blobs_path()).get(os.path.realpath(root))
    if not isinstance(kept, dict) or kept.get("policy") != policy_digest(config_path):
        return set()
    return {tuple(entry) for entry in kept.get("blobs") or [] if _is_content(entry)}


def _is_content(entry) -> bool:
    """Tell whether a recorded entry is a (path, mode, blob id) of text. Takes the entry. Returns
    the answer."""
    return isinstance(entry, (list, tuple)) and len(entry) == 3 and all(isinstance(part, str) for part in entry)
