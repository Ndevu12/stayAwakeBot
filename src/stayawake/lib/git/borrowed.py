#!/usr/bin/env python3
"""A repository saw owns that reads the operator's objects.

    with borrow(operator_repo) as borrowed:        # raises BorrowError when it cannot be made
        borrowed.path                               # the saw-owned bare repository
        borrowed.merge_tree(a, b)                   # AutoMerge | None — object ids, not ref names
        borrowed.materialise(treeish, dest)         # bool — the tree's raw bytes written under dest
        borrowed.run(args, **kw)                    # a git command here, as SAW_OWNED

Every read-only query in `query` also works with `borrowed.path` as its repository, and sees both the
operator's objects and those made here. `write.transfer.adopt_objects` hands objects made here to the
operator's repository.
"""
from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from stayawake.lib.git import attributes, owned
from stayawake.lib.git.contexts import SAW_OWNED
from stayawake.lib.git.merge.tree import AutoMerge, auto_merge
from stayawake.lib.git.run import run, stdout
from stayawake.utils import scratch

_RAW_CHECKOUT = b"* -text -eol -ident -filter -working-tree-encoding\n"


class BorrowError(OSError):
    """The borrowed-objects repository could not be made."""


@dataclass
class Borrowed:
    """A saw-owned bare repository over the operator's objects. See the module docstring."""

    path: Path
    operator_repo: Path
    operator_objects: Path
    attributes: bytes

    def run(self, args: list[str], **kw):
        """Run a git command in this repository as SAW_OWNED. Takes run()'s keyword arguments."""
        return run(self.path, args, context=SAW_OWNED, **kw)

    def merge_tree(self, a: str, b: str) -> AutoMerge | None:
        """Git's clean 3-way merge of `a` and `b`, written here. Returns None when there is none."""
        return auto_merge(self.path, a, b)

    @contextlib.contextmanager
    def attributes_then(self, extra: bytes) -> Iterator[None]:
        """Hold the operator's attributes followed by `extra` while the block runs. Takes the
        lines to append."""
        info = self.path / "info" / "attributes"
        info.write_bytes(self.attributes + extra)
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                info.write_bytes(self.attributes)

    def filtered(self, paths: list[bytes]) -> set[bytes] | None:
        """The paths among `paths` the operator's attributes send through a filter. Takes paths
        relative to the working tree. Returns them, or None when git could not say."""
        if not paths:
            return set()
        res = run(self.path, ["check-attr", "-z", "--stdin", "filter"], context=SAW_OWNED,
                  input_text=os.fsdecode(b"\0".join(paths) + b"\0"))
        if res is None or res.returncode != 0:
            return None
        fields = os.fsencode(res.stdout or "").split(b"\0")
        return {fields[i] for i in range(0, len(fields) - 2, 3)
                if fields[i + 2] not in (b"unspecified", b"unset")}

    def materialise(self, treeish: str, dest: str | Path) -> bool:
        """Write `treeish`'s files under `dest` exactly as stored: no filter, end-of-line or encoding
        conversion. Takes the tree-ish and an existing directory. Returns whether every step ran."""
        dest = Path(dest)
        index = self.path / "materialise.index"
        info = self.path / "info" / "attributes"
        env = dict(os.environ, GIT_INDEX_FILE=str(index), GIT_WORK_TREE=str(dest))
        try:
            info.write_bytes(self.attributes + _RAW_CHECKOUT)
            read = self.run(["read-tree", treeish], env=env)
            if read is None or read.returncode != 0:
                return False
            out = self.run(["checkout-index", "-a", "-f"], env=env)
            return out is not None and out.returncode == 0
        except OSError:
            return False
        finally:
            with contextlib.suppress(OSError):
                info.write_bytes(self.attributes)
            with contextlib.suppress(OSError):
                index.unlink()


def object_directory(repo: str | Path) -> Path | None:
    """The absolute object directory of `repo` — for a linked worktree, its main repository's.
    Returns None when git cannot say or it is not a directory."""
    common = stdout(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"]).strip()
    if not common or "\n" in common:
        return None
    objects = Path(common) / "objects"
    return objects if objects.is_dir() else None


def _operator_layout(repo: Path) -> tuple[Path, Path | None, str]:
    """The operator's object directory, working tree (None when bare) and object format."""
    objects = object_directory(repo)
    if objects is None:
        raise BorrowError(f"git could not say where {repo} keeps its objects")
    inside = stdout(repo, ["rev-parse", "--is-inside-work-tree"]).strip() == "true"
    top = stdout(repo, ["rev-parse", "--show-toplevel"]).strip() if inside else ""
    fmt = stdout(repo, ["rev-parse", "--show-object-format"]).strip() or "sha1"
    return objects, (Path(top) if top else None), fmt


def _carried_attributes(repo: Path, worktree: Path | None, common: Path) -> bytes:
    tracked = []
    if worktree is not None:
        listing = run(repo, ["ls-files", "-z"])
        if listing is not None and listing.returncode == 0:
            tracked = [p for p in (listing.stdout or "").split("\0") if p]
    info = attributes.read_regular(common / "info" / "attributes")
    return attributes.carried(worktree, tracked, info)


@contextlib.contextmanager
def borrow(operator_repo: str | Path) -> Iterator[Borrowed]:
    """Make a borrowed-objects repository over `operator_repo`, yield it, and remove it after.
    Raises BorrowError when it cannot be made."""
    operator_repo = Path(operator_repo)
    objects, worktree, fmt = _operator_layout(operator_repo)
    where = scratch.new_dir("a borrowed object store")
    bare = where / "repo.git"
    try:
        yield _make(bare, operator_repo, objects, worktree, fmt)
    finally:
        owned.disown(bare)
        scratch.release_path(where)


def _make(bare: Path, operator_repo: Path, objects: Path, worktree: Path | None,
          fmt: str) -> Borrowed:
    made = run(None, ["init", "--bare", "--quiet", f"--object-format={fmt}", "--template=",
                      str(bare)], context=SAW_OWNED)
    if made is None or made.returncode != 0:
        raise BorrowError(f"git could not create a repository at {bare}")
    owned.own(bare)
    try:
        (bare / "objects" / "info").mkdir(parents=True, exist_ok=True)
        (bare / "objects" / "info" / "alternates").write_text(f"{objects}\n", encoding="utf-8")
        shallow = attributes.read_regular(objects.parent / "shallow", limit=64 << 20)
        if shallow is not None:
            (bare / "shallow").write_bytes(shallow)
        carried = _carried_attributes(operator_repo, worktree, objects.parent)
        (bare / "info").mkdir(exist_ok=True)
        (bare / "info" / "attributes").write_bytes(carried)
    except OSError as exc:
        raise BorrowError(f"could not prepare {bare}: {exc}") from exc
    return Borrowed(bare, operator_repo, objects, carried)
