#!/usr/bin/env python3
"""What saw reads as uncommitted work in an operator's checkout, and what moving the checkout
leaves on disk."""
from __future__ import annotations

import os
import time
import unittest

from stayawake.lib.git.write import amend as gitamend, working_tree
from tests.support.gitrepo import GitSandbox


class _Checkout(GitSandbox):
    def repo_with(self, files: dict[str, str | bytes]) -> "os.PathLike":
        repo = self.new_repo("checkout", user__name="Tester")
        for rel, content in files.items():
            path = repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content if isinstance(content, bytes) else content.encode())
        self.commit(repo, "start")
        return repo

    def touch_later(self, path) -> None:
        later = time.time_ns() + 5_000_000_000
        os.utime(path, ns=(later, later))


class TestAConvertedFileIsClean(_Checkout):
    """Check a file git converts on checkout."""

    def setUp(self):
        super().setUp()
        self.repo = self.repo_with({".gitattributes": "*.bat text eol=crlf\n", "run.bat": "a\n"})
        (self.repo / "run.bat").unlink()
        self.git(self.repo, "checkout", "--", "run.bat")

    def test_a_fresh_checkout_is_clean(self):
        self.assertEqual(b"a\r\n", (self.repo / "run.bat").read_bytes())
        self.assertFalse(working_tree.is_dirty(self.repo))

    def test_a_touched_file_with_the_same_content_is_clean(self):
        self.touch_later(self.repo / "run.bat")
        self.assertFalse(working_tree.is_dirty(self.repo))

    def test_a_changed_file_is_dirty(self):
        (self.repo / "run.bat").write_bytes(b"b\r\n")
        self.touch_later(self.repo / "run.bat")
        self.assertTrue(working_tree.is_dirty(self.repo))


class TestAFilteredFileIsDecidedByItsRecord(_Checkout):
    """Check a file the operator's attributes send through a filter."""

    def setUp(self):
        super().setUp()
        self.repo = self.repo_with({".gitattributes": "*.bin filter=store\n", "data.bin": "x\n"})

    def test_an_untouched_file_is_clean(self):
        time.sleep(0.01)
        self.assertFalse(working_tree.is_dirty(self.repo))

    def test_a_touched_file_counts_as_changed(self):
        self.touch_later(self.repo / "data.bin")
        self.assertTrue(working_tree.is_dirty(self.repo))

    def test_moving_the_checkout_over_it_is_refused_and_touches_nothing(self):
        old = self.rev(self.repo)
        (self.repo / "data.bin").write_text("y\n")
        (self.repo / "gone.txt").write_text("z\n")
        self.git(self.repo, "add", "-A")
        self.git(self.repo, "commit", "-qm", "next")
        new = self.rev(self.repo)
        before = sorted(p.name for p in self.repo.iterdir())
        self.assertFalse(gitamend.point_branch_at(self.repo, "main", old, new))
        self.assertEqual(new, self.rev(self.repo, "refs/heads/main"))
        self.assertEqual(before, sorted(p.name for p in self.repo.iterdir()))
        self.assertEqual("y\n", (self.repo / "data.bin").read_text())


class TestEveryRecordedChangeIsSeen(_Checkout):
    """Check changes the stat data alone reveals."""

    def setUp(self):
        super().setUp()
        self.repo = self.repo_with({".gitattributes": "*.bin filter=store\n", "keep.txt": "v1\n",
                                    "data.bin": "x\n"})

    def test_a_mode_change(self):
        (self.repo / "keep.txt").chmod(0o755)
        self.assertTrue(working_tree.is_dirty(self.repo))

    def test_a_same_size_write_with_its_time_put_back(self):
        path = self.repo / "keep.txt"
        before = os.lstat(path)
        time.sleep(0.01)
        path.write_text("OP\n")
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertTrue(working_tree.is_dirty(self.repo))

    def test_a_filtered_file_recorded_in_the_same_tick_as_the_index_is_clean(self):
        index = self.repo / ".git" / "index"
        recorded = os.lstat(self.repo / "data.bin").st_mtime_ns
        os.utime(index, ns=(recorded, recorded))
        self.assertFalse(working_tree.is_dirty(self.repo))


class TestAttributesGitAppliesAreTheOnesUsed(_Checkout):
    """Check attributes that come from a file the repository does not track."""

    def test_a_move_over_a_file_an_untracked_attributes_file_filters_is_refused(self):
        repo = self.repo_with({"f.s": "one\n"})
        old = self.rev(repo)
        (repo / "f.s").write_text("two\n")
        self.git(repo, "commit", "-qam", "next")
        new = self.rev(repo)
        (repo / ".git" / "info").mkdir(exist_ok=True)
        (repo / ".git" / "info" / "exclude").write_text(".gitattributes\n")
        (repo / ".gitattributes").write_text("*.s filter=rot\n")
        self.assertFalse(gitamend.point_branch_at(repo, "main", old, new))
        self.assertEqual("two\n", (repo / "f.s").read_text())


class TestASubmodulesWorkIsKept(_Checkout):
    """Check a submodule checked out inside the operator's checkout."""

    def setUp(self):
        super().setUp()
        self.sub = self.repo_with({"lib.js": "one\n"})
        self.repo = self.new_repo("outer", user__name="Tester")
        self.write(self.repo, "app.js", "app\n")
        self.git(self.repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                 str(self.sub), "lib")
        self.commit(self.repo, "with lib")

    def test_an_edit_inside_it_is_dirty(self):
        self.assertFalse(working_tree.is_dirty(self.repo))
        (self.repo / "lib" / "lib.js").write_text("changed\n")
        self.assertTrue(working_tree.is_dirty(self.repo))

    def test_an_untracked_file_inside_it_is_dirty(self):
        (self.repo / "lib" / "new.js").write_text("mine\n")
        self.assertTrue(working_tree.is_dirty(self.repo))

    def test_moving_away_from_it_leaves_its_directory(self):
        (self.repo / "lib" / "new.js").write_text("mine\n")
        head = self.rev(self.repo)
        entries = {p: e for p, e in working_tree._tree_entries(self.repo, head).items()
                   if p != b"lib"}
        self.assertTrue(working_tree._write_paths(self.repo, self.repo, head, entries, [b"lib"]))
        self.assertEqual("mine\n", (self.repo / "lib" / "new.js").read_text())
        self.assertTrue((self.repo / "lib" / ".git").exists())


if __name__ == "__main__":
    unittest.main()
