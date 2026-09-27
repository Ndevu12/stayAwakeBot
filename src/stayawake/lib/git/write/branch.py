#!/usr/bin/env python3
"""Reference mutations in the operator's repository, made with `update-ref` only."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.contexts import Context
from stayawake.lib.git.run import UNTRUSTED, run_ok, stdout, stdout_bytes_fed
from stayawake.lib.git.write.checkouts import checked_out_at

ZERO = "0" * 40


def refs_under(repo: str | Path, *prefixes: str, context: Context = UNTRUSTED) -> dict[str, str]:
    """`{refname: id}` for every ref under `prefixes` in `repo` that is not a symbolic ref, such as
    `refs/remotes/origin/HEAD`, which names another ref rather than a commit."""
    out = stdout(repo, ["for-each-ref", "--format=%(objectname) %(refname) %(symref)", *prefixes],
                 context=context)
    found = {}
    for line in out.splitlines():
        oid, _, rest = line.partition(" ")
        name, _, target = rest.partition(" ")
        if oid and name and not target:
            found[name] = oid
    return found


def update_refs(repo: str | Path, changes: list[tuple[str, str, str]], *,
                context: Context = UNTRUSTED) -> bool:
    """Apply every `(ref, new, old)` in one transaction, each only while the ref is still at `old`.
    An empty `new` deletes; an empty `old` requires the ref to be absent. A symbolic ref is acted
    on itself, never on the ref it names. Returns whether all applied — on False none did."""
    if not changes:
        return True
    lines = []
    for ref, new, old in changes:
        lines.append("option no-deref")
        if not new:
            lines.append(f"delete {ref} {old}")
        elif not old:
            lines.append(f"create {ref} {new}")
        else:
            lines.append(f"update {ref} {new} {old}")
    return stdout_bytes_fed(repo, ["update-ref", "--stdin"], ("\n".join(lines) + "\n").encode(),
                            context=context) is not None


def set_branch(repo: str | Path, name: str, new: str) -> bool:
    """Point `refs/heads/<name>` at `new`, whatever it held. Returns whether git moved it."""
    return run_ok(repo, ["update-ref", f"refs/heads/{name}", new], context=UNTRUSTED)


def delete_branch(repo: str | Path, name: str) -> bool:
    """Delete local branch `name`. Only ever called on the auto-generated fix branch — never a
    real branch. A branch some checkout has checked out is left in place, as `branch -D` does.
    Returns whether it is gone."""
    try:
        if checked_out_at(repo, name) is not None:
            return False
    except OSError:
        return False
    tip = stdout(repo, ["rev-parse", "--verify", "--quiet", f"refs/heads/{name}"],
                 context=UNTRUSTED).strip()
    if not tip:
        return False
    return run_ok(repo, ["update-ref", "-d", f"refs/heads/{name}", tip], context=UNTRUSTED)
