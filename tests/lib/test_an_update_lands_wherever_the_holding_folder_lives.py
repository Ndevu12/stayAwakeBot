"""A checked update reaches the operator's repository wherever saw's holding repository lives, and a
failure says why."""
from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

from stayawake.lib.git import owned
from stayawake.lib.git.borrowed import object_directory
from stayawake.lib.git.write import replayed, transfer
from stayawake.utils import scratch
from tests.support.gitrepo import GitSandbox


class AnUpdateLandsWhereverTheHoldingFolderLives(GitSandbox):

    def _operator_and_holding(self) -> tuple[Path, Path, str, str]:
        operator = self.new_repo("operator")
        self.write(operator, "a.txt", "one\n")
        base = self.commit(operator, "base")
        holding = self.root / "holding"
        self.git(self.root, "clone", "-q", str(operator), str(holding))
        self.git(holding, "config", "user.email", "t@t.test")
        self.git(holding, "config", "user.name", "T")
        self.write(holding, "b.txt", "two\n")
        update = self.commit(holding, "update")
        owned.own(holding)
        return operator, holding, base, update

    def _adopt_recording_where_it_packs(self, operator, holding, base, update) -> Path:
        packed_at = []
        real = transfer.stdout_bytes_fed

        def recording(repo, args, *rest, **options):
            if "pack-objects" in args:
                packed_at.append(Path(args[-1]))
            return real(repo, args, *rest, **options)

        with mock.patch.object(transfer, "stdout_bytes_fed", recording):
            self.assertEqual(transfer.adopt_objects(operator, holding, [update], [base]), "")
        self.assertEqual(len(packed_at), 1)
        self.assertEqual(self.git(operator, "cat-file", "-t", update).strip(), "commit")
        self.assertFalse(packed_at[0].parent.exists())
        return packed_at[0]

    def test_the_new_objects_are_packed_on_the_holding_repositorys_filesystem(self):
        operator, holding, base, update = self._operator_and_holding()
        store = object_directory(holding)
        packed = self._adopt_recording_where_it_packs(operator, holding, base, update)
        self.assertEqual(os.stat(packed.parent.parent).st_dev, os.stat(store).st_dev)

    def test_with_scratch_on_another_filesystem_the_objects_are_packed_beside_the_holding_repository(self):
        operator, holding, base, update = self._operator_and_holding()
        store = object_directory(holding)
        with mock.patch.object(scratch, "_same_filesystem", return_value=False):
            packed = self._adopt_recording_where_it_packs(operator, holding, base, update)
        self.assertEqual(packed.parent.parent, store)
        self.assertEqual([p.name for p in store.iterdir() if p.name.startswith(scratch.ROOT_PREFIX)], [])

    def test_a_failed_pack_leaves_no_unfinished_files_in_the_holding_repository(self):
        operator, holding, base, update = self._operator_and_holding()
        pack_dir = object_directory(holding) / "pack"
        pack_dir.mkdir(parents=True, exist_ok=True)
        (pack_dir / "tmp_pack_earlier").write_bytes(b"")
        real = transfer.stdout_bytes_fed

        def failing(repo, args, *rest, **options):
            if "pack-objects" in args:
                (pack_dir / "tmp_pack_left").write_bytes(b"")
                (pack_dir / "tmp_idx_left").write_bytes(b"")
                return None
            return real(repo, args, *rest, **options)

        with mock.patch.object(transfer, "stdout_bytes_fed", failing):
            why = transfer.adopt_objects(operator, holding, [update], [base])
        self.assertEqual(why, "the new objects could not be packed")
        self.assertEqual(sorted(p.name for p in pack_dir.iterdir() if p.name.startswith("tmp_")), ["tmp_pack_earlier"])
        self.assertEqual([p.name for p in pack_dir.parent.iterdir() if p.name.startswith(scratch.ROOT_PREFIX)], [])

    def test_apply_says_why_the_update_did_not_arrive(self):
        operator = self.new_repo("operator")
        self.write(operator, "a.txt", "one\n")
        base = self.commit(operator, "base")
        into = self.root / "hold"
        into.mkdir()
        result = replayed.Written(top=operator, git_dir=operator / ".git", holding=into, files_after=base, files=(),
                                  before={}, digests={}, index=(), refs=(("refs/heads/main", "0" * 40, base),),
                                  head_before="ref: refs/heads/main", head_after="ref: refs/heads/main",
                                  state_removed=(), stash_log=None, base=base)
        with mock.patch.object(replayed, "adopt_objects", return_value="the new objects could not be packed"):
            said = replayed.write(result)
        self.assertEqual(said, "the update could not be copied into the open folder: the new objects could not be packed")
