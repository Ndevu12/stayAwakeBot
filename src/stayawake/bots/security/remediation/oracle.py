#!/usr/bin/env python3
"""Whether content still confirms a payload — asked of a path in a tree, or of bytes."""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.lib import git as gitutil
from stayawake.lib.git.run import stdout_bytes
from stayawake.utils import scratch


def payload_matchers(signatures):
    """The by-matcher signatures minus the groups that need the repo, history, or install state —
    the matchers that judge a single file's own content."""
    return ({k: v for k, v in signatures.items()
             if k not in ("git-history", "dependency-audit", "installed-package-audit")}
            if isinstance(signatures, dict) else signatures)


def content_confirms(content: bytes, path: str, payload, allowlist, opts,
                      is_symlink: bool = False) -> str | None:
    """The confirmed signature id `content` triggers when scanned as `path`, or None. A truthy
    result — a signature id or an errored token — means treat the content as unclean."""
    import os
    import tempfile
    from stayawake.bots.security import scanner as _scanner
    from stayawake.bots.security.targets.base import Target
    tmp = str(scratch.new_dir("the amend oracle"))
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
        scratch.release_path(Path(tmp))
    if result.error is not None:
        return "scan-error"
    return next((getattr(f, "signature_id", "confirmed") for f in result.findings
                 if getattr(f, "path", "") == path
                 and getattr(f, "confidence", None) == CONFIRMED
                 and not getattr(f, "advisory_only", False)), None)


def survives(repo, signatures, allowlist, opts) -> object:
    """`check(treeish, path) -> str | None` for whether a path's content in a tree confirms a payload.
    Takes the repo, the by-matcher signatures, the allowlist, and the scan options. Returns the check;
    a truthy result — a signature id, or an unreadable/errored token — means treat the path as unclean."""
    payload = payload_matchers(signatures)
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
                scanned[(path, sha)] = content_confirms(blob, path, payload, allowlist, opts,
                                                         is_symlink=(entry[0] == "120000"))
        return scanned[(path, sha)]

    return check
