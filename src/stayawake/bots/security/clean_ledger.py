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
from stayawake.utils import atomicwrite

cache_path = hookscript.cache_path


def load_cache() -> dict:
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
    """Read the clean scans a run from git's settings remembers. Returns them by repository."""
    try:
        held = json.loads(hookscript.settings_scan_path().read_text())
    except (OSError, ValueError):
        return {}
    return held if isinstance(held, dict) else {}


def remember_settings_scan(root: Path, key: str) -> None:
    """Remember a clean scan a run from git's settings made, apart from saw's list of repositories it
    keeps current. Takes the root and the clean key. A write that fails is skipped."""
    held = {r: k for r, k in settings_scans().items() if os.path.isdir(r)}
    held[os.path.realpath(root)] = key
    atomicwrite.replace(hookscript.settings_scan_path(), json.dumps(held))


def remember(root: Path, key: str) -> None:
    """Record a scanned repository, and the clean scan it may skip next time. Takes the root and
    the clean key, or "" when the scan was not clean. A write that fails is skipped."""
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


def load_applied() -> dict:
    try:
        held = json.loads(applied_path().read_text())
    except (OSError, ValueError):
        return {}
    return held if isinstance(held, dict) else {}


def remember_applied(root: Path, key: str) -> None:
    """Record a tree govern let into a repository, clean or residue. Takes the root and the key.
    A write that fails is skipped."""
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
