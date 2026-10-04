#!/usr/bin/env python3
"""What a commit that delivered a payload brought with it, read from the history."""
from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security.remediation import delivery
from stayawake.lib.git import query
from stayawake.lib.git.merge import detect as mergedetect
from tests.support.gitrepo import GitSandbox


class _History(GitSandbox):

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("history")
        self.write(self.d, "README.md", "readme\n")
        self.write(self.d, "src/app.js", "app\n")
        self.root_commit = self.commit(self.d, "the project")

    def blob(self, ref, path):
        return self.git(self.d, "rev-parse", f"{ref}:{path}").strip()


class TestWhatACommitBrought(_History):

    def test_an_ordinary_commit_brings_what_it_added_and_names_what_it_changed(self):
        self.write(self.d, "fonts/pad.woff2", "pad\n")
        self.write(self.d, "src/app.js", "app changed\n")
        commit = self.commit(self.d, "delivery")
        brought = delivery.brought_by(self.d, commit)
        self.assertFalse(brought.parentless)
        self.assertEqual((("fonts/pad.woff2", self.blob(commit, "fonts/pad.woff2")),),
                         brought.added)
        self.assertEqual(("src/app.js",), brought.changed)

    def test_a_merge_brings_only_what_neither_parent_had(self):
        self.git(self.d, "checkout", "-q", "-b", "side")
        self.write(self.d, "src/feature.js", "genuine side work\n")
        self.commit(self.d, "side work")
        self.git(self.d, "checkout", "-q", "main")
        self.git(self.d, "merge", "-q", "--no-ff", "--no-commit", "side")
        self.write(self.d, "fonts/pad.woff2", "pad\n")
        merge = self.commit(self.d, "merge side")
        brought = delivery.brought_by(self.d, merge)
        self.assertEqual(["fonts/pad.woff2"], [p for p, _b in brought.added])
        self.assertNotIn("src/feature.js", brought.changed)

    def test_a_first_commit_brings_every_file_it_holds(self):
        brought = delivery.brought_by(self.d, self.root_commit)
        self.assertTrue(brought.parentless)
        self.assertEqual(["README.md", "src/app.js"], [p for p, _b in brought.added])

    def test_a_moved_file_is_added_at_its_new_path(self):
        self.git(self.d, "mv", "src/app.js", "app.js")
        commit = self.commit(self.d, "move")
        self.assertEqual(["app.js"], [p for p, _b in delivery.brought_by(self.d, commit).added])

    def test_what_git_could_not_read_is_unread_never_empty(self):
        missing = "0" * 40
        with self.assertRaises(query.Unread):
            delivery.brought_by(self.d, missing)
        self.assertEqual({missing: None}, delivery.brought_by_each(self.d, [missing]))


class TestTheFirstCarrier(_History):

    def test_the_commit_whose_parents_hold_no_payload_version_is_the_delivery(self):
        self.write(self.d, "fonts/x.woff2", "payload\n")
        delivered = self.commit(self.d, "delivery")
        self.write(self.d, "other.txt", "x\n")
        self.commit(self.d, "unrelated")
        self.write(self.d, "fonts/x.woff2", "payload v2\n")
        changed = self.commit(self.d, "payload changed")
        found = delivery.first_carriers(self.d, {"fonts/x.woff2": [delivered, changed]})
        self.assertEqual({delivered: ("fonts/x.woff2",)}, found)

    def test_a_commit_git_could_not_read_raises(self):
        with self.assertRaises(query.Unread):
            delivery.first_carriers(self.d, {"README.md": ["0" * 40]})


class TestTheOrigin(_History):

    def _brought(self, commit, added=()):
        return delivery.Brought(commit, tuple((p, "b" * 40) for p in added))

    def test_a_file_a_delivery_added_names_it(self):
        found = delivery.origin_of("pad.txt", {"c" * 40: ("x.js",)},
                                  {"c" * 40: self._brought("c" * 40, ["pad.txt"])})
        self.assertEqual(delivery.Origin("c" * 40, ("x.js",)), found)

    def test_a_file_no_delivery_added_is_untied(self):
        found = delivery.origin_of("own.txt", {"c" * 40: ("x.js",)},
                                  {"c" * 40: self._brought("c" * 40, ["pad.txt"])})
        self.assertEqual(delivery.Origin(), found)

    def test_a_delivery_git_could_not_read_makes_the_origin_unread(self):
        found = delivery.origin_of("own.txt", {"c" * 40: ("x.js",)}, {"c" * 40: None})
        self.assertTrue(found.unread)
        self.assertEqual("", found.commit)


class TestBornAtMerge(_History):

    def _gitlink(self):
        sub = self.root_commit
        self.git(self.d, "update-index", "--add", "--cacheinfo", f"160000,{sub},vendor/sub")
        self.git(self.d, "commit", "-qm", "add a submodule")
        return self.rev(self.d)

    def test_it_answers_as_the_stored_entry_of_each_parent_does(self):
        parent = self._gitlink()
        self.write(self.d, "dir/new.txt", "new\n")
        self.git(self.d, "add", "dir/new.txt")
        self.git(self.d, "commit", "-qm", "child")
        child = self.rev(self.d)
        paths = ["README.md", "src", "vendor/sub", "vendor/sub/inner.js", "dir/new.txt", "absent"]
        expected = {p for p in paths if not query.stores_path(self.d, parent, p)}
        self.assertEqual(expected, mergedetect.born_at_merge(self.d, child, paths))
        self.assertEqual({"vendor/sub", "vendor/sub/inner.js", "dir/new.txt", "absent"}, expected)

    def test_it_reads_each_parent_once(self):
        self.git(self.d, "checkout", "-q", "-b", "side")
        self.write(self.d, "side.txt", "side\n")
        self.commit(self.d, "side")
        self.git(self.d, "checkout", "-q", "main")
        self.git(self.d, "merge", "-q", "--no-ff", "--no-commit", "side")
        for n in range(30):
            self.write(self.d, f"new/{n}.txt", f"{n}\n")
        merge = self.commit(self.d, "merge")
        real = query._entries
        with mock.patch.object(query, "_entries", side_effect=real) as read:
            born = mergedetect.born_at_merge(self.d, merge, [f"new/{n}.txt" for n in range(30)])
        self.assertEqual(30, len(born))
        self.assertEqual(2, read.call_count)



class TestSweepMerges(_History):
    def _finding(self, sha, related):
        return SimpleNamespace(commit_sha=sha, related_paths=related)

    def test_two_findings_on_one_merge_take_out_the_paths_of_both(self):
        self.write(self.d, "a.js", "a\n")
        sha = self.commit(self.d, "one")
        found = [(self._finding(sha, ("a.js",)), {"a.js"}), (self._finding(sha, ("b.js",)), {"b.js"})]
        with mock.patch.object(delivery, "confirmed_commits", return_value=found), \
                mock.patch.object(delivery, "swept_by", side_effect=[["a.js"], ["b.js"]]):
            sweeps = delivery.sweep_merges(self.d, [])
        self.assertEqual({sha: ("a.js", "b.js")}, sweeps.swept)

    def test_a_reported_commit_that_names_none_is_named_with_its_files(self):
        found = [(self._finding("0" * 40, ("a.js",)), {"a.js"})]
        with mock.patch.object(delivery, "confirmed_commits", return_value=found):
            sweeps = delivery.sweep_merges(self.d, [])
        self.assertEqual(["000000000000: a.js"], sweeps.unresolved)
        self.assertEqual({}, sweeps.swept)

class TestMentions(_History):
    def test_a_file_is_counted_by_the_other_files_that_name_it(self):
        self.write(self.d, "fonts/icons.woff2", "font bytes\n")
        self.write(self.d, "fonts/README.md", "uses icons.woff2\n")
        self.write(self.d, "src/app.css", "src: url(fonts/icons.woff2);\n")
        self.write(self.d, "src/other.css", "nothing here\n")
        self.commit(self.d, "assets")
        found = delivery.files_naming(self.d, ["fonts/icons.woff2", "fonts/README.md"])
        self.assertEqual({"fonts/README.md", "src/app.css"}, set(found["fonts/icons.woff2"]))
        self.assertEqual(frozenset(), found["fonts/README.md"])

    def test_nothing_is_counted_when_a_file_could_not_be_read(self):
        self.write(self.d, "fonts/icons.woff2", "font bytes\n")
        self.commit(self.d, "assets")
        with mock.patch.object(delivery, "read_blobs", return_value=({}, {})):
            self.assertIsNone(delivery.files_naming(self.d, ["fonts/icons.woff2"]))
