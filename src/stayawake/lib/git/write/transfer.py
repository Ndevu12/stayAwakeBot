#!/usr/bin/env python3
"""Hand objects a saw-owned repository made to the operator's repository. The objects are packed there
and the pack placed in the operator's `objects/pack`, the `.pack` first and the `.idx` last; every
object is then confirmed present with `cat-file --batch-check` before the caller points a ref at
any of them."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from stayawake.lib.git.borrowed import object_directory
from stayawake.lib.git.contexts import Context
from stayawake.lib.git.run import SAW_OWNED, UNTRUSTED, stdout, stdout_bytes_fed
from stayawake.utils import scratch

_EMPTY_PACK_BYTES = 32


def _rev_input(tips: list[str], known: list[str]) -> bytes:
    return ("\n".join([*tips, *[f"^{k}" for k in known]]) + "\n").encode()


def reachable_objects(source: str | Path, tips: list[str], known: list[str]) -> list[str] | None:
    """Every object id `tips` reach in `source` that `known` do not. None when git cannot say."""
    out = stdout_bytes_fed(source, ["rev-list", "--objects", "--stdin"], _rev_input(tips, known),
                           context=SAW_OWNED)
    if out is None:
        return None
    return [line.split(b" ", 1)[0].decode() for line in out.splitlines() if line.strip()]


def missing_objects(repo: str | Path, oids: list[str]) -> list[str] | None:
    """The ids among `oids` that `repo` does not hold. None when git cannot say."""
    if not oids:
        return []
    out = stdout_bytes_fed(repo, ["cat-file", "--batch-check=%(objectname)"],
                           ("\n".join(oids) + "\n").encode(), context=UNTRUSTED)
    if out is None:
        return None
    return [line.split(b" ", 1)[0].decode() for line in out.splitlines()
            if line.rstrip().endswith(b" missing")]


def _place(src: Path, dest_dir: Path) -> None:
    dest = dest_dir / src.name
    if dest.exists():
        return
    staging = dest_dir / f".saw-incoming-{os.getpid()}-{src.name}"
    shutil.copyfile(src, staging)
    os.chmod(staging, 0o444)
    os.replace(staging, dest)


def adopt_objects(repo: str | Path, source: str | Path, tips: list[str],
                  known: list[str]) -> str:
    """Make every object `tips` reach in `source` and `known` do not present in `repo`.

    Takes the operator repository, the saw-owned repository holding the objects, the tips, and
    ids the operator already has. Returns "" once each object is confirmed present in `repo`, else
    why not.
    """
    wanted = reachable_objects(source, tips, known)
    if wanted is None:
        return "the new objects could not be listed"
    missing = missing_objects(repo, wanted)
    if missing is None:
        return "the operator repository could not be asked which objects it holds"
    if not missing:
        return ""
    store = object_directory(repo)
    if store is None:
        return f"{repo} has no object store"
    staging = scratch.new_dir("objects handed to the operator repository")
    try:
        named = stdout_bytes_fed(source, ["pack-objects", "--revs", "--local", "-q",
                                          str(staging / "pack")],
                                 _rev_input(tips, known), context=SAW_OWNED)
        if not named:
            return "the new objects could not be packed"
        name = f"pack-{named.decode().strip()}"
        pack, index = staging / f"{name}.pack", staging / f"{name}.idx"
        if not (pack.is_file() and index.is_file()):
            return "the new objects could not be packed"
        if pack.stat().st_size > _EMPTY_PACK_BYTES:
            try:
                (store / "pack").mkdir(parents=True, exist_ok=True)
                _place(pack, store / "pack")
                _place(index, store / "pack")
            except OSError as exc:
                return f"the new objects could not be written to {store}: {exc}"
    finally:
        scratch.release_path(staging)
    still = missing_objects(repo, missing)
    if still is None:
        return "the operator repository could not confirm the new objects"
    if still:
        return f"{len(still)} new object(s) did not reach the operator repository"
    return ""


def resolved(repo: str | Path, rev: str, *, context: Context = UNTRUSTED) -> str:
    """The commit id `rev` names in `repo`, or ""."""
    return stdout(repo, ["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"],
                  context=context).strip()
