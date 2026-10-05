#!/usr/bin/env python3
"""`saw fix amend` takes malware out of every commit it rewrites."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from stayawake.bots.security.pr import amend as amendmod
from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.pr.outcome import Cause
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_amend import _AmendFixture

LOADER = "global['_V']=function(x){return x};require('child_process').exec('id');\n"
STAGE2 = "global['_V']=function(x){return x};require('child_process').exec('whoami');\n"
STAGE3 = "global['_V']=function(x){return x};require('child_process').exec('uname');\n"


class _Rewrite(_AmendFixture):

    def setUp(self):
        super().setUp()
        self.base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()

    def evil_merge(self):
        self.write(self.d, "docs/guide.md", "# guide\n")
        self.commit(self.d, "add docs")
        self.git(self.d, "merge", "--no-commit", "--no-ff", "feature")
        self.write(self.d, "vendor/x/loader.js", LOADER)
        self.write(self.d, "vendor/x/stage2.js", STAGE2)
        return self.commit(self.d, "Merge pull request #7 from feature")

    def rename_and_change_then_delete(self):
        self.git(self.d, "rm", "-q", "vendor/x/stage2.js")
        self.write(self.d, "vendor/x/lib/s2.js", STAGE3)
        self.write(self.d, "src/app.js", "export const app = 1;\n")
        self.commit(self.d, "move stage two and add the app")
        self.git(self.d, "rm", "-q", "vendor/x/lib/s2.js")
        self.commit(self.d, "remove it by hand")

    def run_amend(self):
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures())
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                 pusher=lambda *a: PushResult(True), resolver=None)


    def holds(self, ref, path):
        return self.git_may_fail(self.d, "cat-file", "-e", f"{ref}:{path}").returncode == 0

    def ever_holds(self, text):
        blob = self._blob_of(text)
        return blob in self.git(self.d, "rev-list", "--objects", self.base).split()

    def _blob_of(self, text):
        scratch = self.d.parent / "blob-of.txt"
        scratch.write_text(text)
        return self.git(self.d, "hash-object", str(scratch)).strip()


class TestTheRewriteIsReadInFull(_Rewrite):

    def test_a_payload_renamed_and_changed_after_the_merge_is_taken_out(self):
        self.evil_merge()
        self.rename_and_change_then_delete()
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        for commit in self.git(self.d, "rev-list", self.base).split():
            self.assertNotEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                                     f"{commit}:vendor/x/lib/s2.js").returncode)
        self.assertEqual("export const app = 1;\n",
                         self.git(self.d, "show", f"{self.base}:src/app.js"))

    def test_a_copy_under_another_name_elsewhere_still_holds_the_run_back(self):
        self.git(self.d, "checkout", "-q", "-b", "other")
        self.write(self.d, "tools/s3.js", STAGE3)
        self.commit(self.d, "a copy")
        self.git(self.d, "checkout", "-q", self.base)
        self.evil_merge()
        self.rename_and_change_then_delete()
        outcome = self.run_amend()
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._causes(outcome))

    def test_versions_it_could_not_list_are_named_for_review(self):
        self.evil_merge()
        self.rename_and_change_then_delete()
        with mock.patch.object(amendmod.pushed, "history_entries", return_value=None):
            outcome = self.run_amend()
        self.assertIn(Cause.REMOVAL_NOT_CONFIRMED, self._causes(outcome))
        self.assertTrue(outcome.needs_review)

    def test_a_copy_of_the_merges_payload_under_another_name_is_taken_out(self):
        self.evil_merge()
        self.write(self.d, "lib/copy.js", STAGE2)
        self.commit(self.d, "copy the stage")
        self.git(self.d, "rm", "-q", "lib/copy.js")
        self.commit(self.d, "remove the copy")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.ever_holds(STAGE2))

    def test_a_tag_on_a_taken_out_copy_is_named(self):
        self.evil_merge()
        self.rename_and_change_then_delete()
        self.git(self.d, "tag", "kept-copy", self._blob_of(STAGE3))
        outcome = self.run_amend()
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._causes(outcome))
        self.assertTrue(outcome.needs_review)

    def test_a_confirmed_version_still_held_after_the_rewrite_stops_the_push(self):
        self.evil_merge()
        self.rename_and_change_then_delete()
        with mock.patch.object(amendmod, "_place_history_finding", lambda *a, **k: None):
            outcome = self.run_amend()
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._causes(outcome))


class TestEveryRewrittenVersionIsJudged(_Rewrite):

    def test_a_payload_moved_and_kept_at_the_tip_is_taken_out(self):
        self.evil_merge()
        self.git(self.d, "rm", "-q", "vendor/x/stage2.js")
        self.write(self.d, "dist/s3.js", STAGE3)
        self.commit(self.d, "build the stage")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.ever_holds(STAGE3))

    def test_a_side_branch_from_before_the_merge_is_cleaned_too(self):
        self.git(self.d, "checkout", "-q", "-b", "side")
        self.write(self.d, "tools/s3.js", STAGE3)
        self.commit(self.d, "add a tool")
        self.git(self.d, "rm", "-q", "tools/s3.js")
        self.commit(self.d, "drop the tool")
        self.git(self.d, "checkout", "-q", self.base)
        self.evil_merge()
        self.git(self.d, "merge", "-q", "--no-ff", "-m", "Merge side", "side")
        self.git(self.d, "branch", "-q", "-D", "side")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.ever_holds(STAGE3))

    def test_a_side_branch_copy_merged_after_the_infection_and_removed_later_is_taken_out(self):
        self.git(self.d, "checkout", "-q", "-b", "side")
        self.write(self.d, "tools/z.js", STAGE3)
        self.commit(self.d, "add a tool")
        self.git(self.d, "checkout", "-q", self.base)
        self.evil_merge()
        self.git(self.d, "merge", "-q", "--no-ff", "-m", "Merge side", "side")
        self.git(self.d, "branch", "-q", "-D", "side")
        self.git(self.d, "rm", "-q", "tools/z.js")
        self.commit(self.d, "drop the tool")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.ever_holds(STAGE3))

    def test_a_payload_under_a_name_that_is_not_utf8_is_taken_out(self):
        self.evil_merge()
        scratch = self.d.parent / "payload.txt"
        scratch.write_text(STAGE3)
        blob = self.git(self.d, "hash-object", "-w", str(scratch)).strip()
        name = os.fsdecode(b"lib/\xff\xfe.js")
        self.git(self.d, "update-index", "--add", "--cacheinfo", f"100644,{blob},{name}")
        self.git(self.d, "commit", "-qm", "a file under an odd name")
        self.git(self.d, "rm", "-q", "--cached", "--", name)
        self.git(self.d, "commit", "-qm", "drop it")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.ever_holds(STAGE3))

    def test_a_payload_kept_at_the_tip_under_a_name_that_is_not_utf8_is_taken_out(self):
        self.evil_merge()
        name = os.fsdecode(b"dist/\xff\xfe.js")
        try:
            self.write(self.d, name, STAGE3)
        except (OSError, UnicodeError):
            self.skipTest("this filesystem refuses a file name that is not UTF-8")
        self.commit(self.d, "build the stage under an odd name")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.ever_holds(STAGE3))

    def test_a_confirmed_file_the_merge_added_is_removed_without_asking(self):
        from stayawake.bots.security.pr.resolve import KEEP, DeliveryAnswer, DeliveryQuestion
        asked = []

        def keep(question):
            if isinstance(question, DeliveryQuestion):
                asked.extend(f.path for f in question.files)
                return DeliveryAnswer(KEEP, ())
            return None

        self.write(self.d, "docs/guide.md", "# guide\n")
        self.commit(self.d, "add docs")
        self.git(self.d, "merge", "--no-commit", "--no-ff", "feature")
        self.write(self.d, "vendor/x/loader.js", LOADER)
        self.write(self.d, "dist/stage2.js", STAGE2)
        self.commit(self.d, "Merge pull request #7 from feature")
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures())
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                          pusher=lambda *a: PushResult(True), resolver=keep)
        self.assertNotIn("dist/stage2.js", asked)
        self.assertFalse(self.ever_holds(STAGE2))


class TestWhatTheRewriteLeavesAlone(_Rewrite):

    def test_a_file_left_for_recovery_keeps_its_tip_and_loses_older_payloads(self):
        self.evil_merge()
        self.write(self.d, "tests/fixtures/sample.js", STAGE2.replace("whoami", "date"))
        self.commit(self.d, "test: sample v1")
        self.write(self.d, "tests/fixtures/sample.js", STAGE3)
        self.commit(self.d, "test: sample v2")
        outcome = self.run_amend()
        self.assertIn(Cause.PAYLOAD_NEEDS_MANUAL_RECOVERY, self._causes(outcome))
        self.assertTrue(self.holds_at(self.base, "tests/fixtures/sample.js", STAGE3))
        self.assertFalse(self.ever_holds(STAGE2.replace("whoami", "date")))

    def test_keeping_a_file_keeps_only_the_version_shown(self):
        from stayawake.bots.security.pr.resolve import KEEP, DeliveryAnswer, DeliveryQuestion
        from stayawake.bots.security.pr.resolve import Resolution
        shown = "var _0x1a2b=['\\x63\\x68\\x69\\x6c\\x64'];eval(atob('Y29uc29sZS5sb2coMSk='));\n"
        asked = []

        def keep(question):
            asked.append(getattr(question, "path", ""))
            if isinstance(question, DeliveryQuestion):
                return DeliveryAnswer(KEEP, ())
            return Resolution(KEEP)

        self.evil_merge()
        self.write(self.d, "lib/s3.js", STAGE3)
        self.commit(self.d, "an earlier version")
        self.write(self.d, "lib/s3.js", shown)
        self.commit(self.d, "the version at the tip")
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures())
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                          pusher=lambda *a: PushResult(True), resolver=keep)
        self.assertIn("lib/s3.js", asked)
        self.assertTrue(self.holds_at(self.base, "lib/s3.js", shown))
        self.assertFalse(self.ever_holds(STAGE3))

    def test_an_older_version_carrying_a_loader_goes_and_the_tip_stays(self):
        legit = "export function add(a, b) { return a + b; }\n"
        self.write(self.d, "lib/app.js", legit)
        self.commit(self.d, "the app")
        self.evil_merge()
        self.write(self.d, "lib/app.js", LOADER + legit)
        self.commit(self.d, "inject")
        self.write(self.d, "lib/app.js", legit + "export const two = 2;\n")
        self.commit(self.d, "clean again")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.ever_holds(LOADER + legit))
        self.assertTrue(self.holds_at(self.base, "lib/app.js", legit + "export const two = 2;\n"))

    def test_a_file_moved_under_an_allowlisted_folder_does_not_block_the_cleanup(self):
        self.write(self.d, "tests/fixtures/sample.js", STAGE3)
        signatures = sorted({f.signature_id for f in scan_target(
            LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures()).findings
            if f.path == "tests/fixtures/sample.js"})
        (self.d / "tests/fixtures/sample.js").unlink()
        allowlist = [{"signature": s, "path_glob": "test/fixtures/*"} for s in signatures]
        self.evil_merge()
        self.write(self.d, "tests/fixtures/sample.js", STAGE3)
        self.commit(self.d, "test: worm sample")
        self.git(self.d, "mv", "tests", "test")
        self.commit(self.d, "rename tests/ to test/")
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures(),
                           allowlist)
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            outcome = amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), allowlist,
                                    "t", pusher=lambda *a: PushResult(True), resolver=None)
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.holds(self.base, "vendor/x/loader.js"))
        self.assertTrue(self.holds(self.base, "test/fixtures/sample.js"))

    def run_amend_with(self, allowlist):
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures(),
                           allowlist)
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), allowlist,
                                 "t", pusher=lambda *a: PushResult(True), resolver=None)

    def holds_at(self, ref, path, text):
        return self.holds(ref, path) and self.git(self.d, "show", f"{ref}:{path}") == text

    def test_an_allowlisted_file_stays_and_other_copies_go(self):
        self.write(self.d, "test/fixtures/sample.js", STAGE3)
        signatures = sorted({f.signature_id for f in scan_target(
            LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures()).findings
            if f.path == "test/fixtures/sample.js"})
        (self.d / "test/fixtures/sample.js").unlink()
        self.evil_merge()
        self.write(self.d, "src/boot.js", STAGE3)
        added = self.commit(self.d, "add boot")
        self.git(self.d, "rm", "-q", "src/boot.js")
        self.write(self.d, "test/fixtures/sample.js", STAGE3)
        self.commit(self.d, "drop boot, add a fixture")
        outcome = self.run_amend_with(
            [{"signature": s, "path_glob": "test/fixtures/*"} for s in signatures])
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertTrue(self.holds_at(self.base, "test/fixtures/sample.js", STAGE3))
        rewritten = self.git(self.d, "log", "--format=%H", f"--grep=add boot", self.base).split()
        self.assertTrue(rewritten and rewritten[0] != added)
        self.assertFalse(self.holds(rewritten[0], "src/boot.js"))

    def test_an_allowlisted_copy_on_another_branch_does_not_stop_the_rest(self):
        self.write(self.d, "test/fixtures/sample.js", STAGE3)
        signatures = sorted({f.signature_id for f in scan_target(
            LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures()).findings
            if f.path == "test/fixtures/sample.js"})
        self.git(self.d, "checkout", "-q", "-b", "samples")
        self.git(self.d, "add", "test/fixtures/sample.js")
        self.commit(self.d, "a sample")
        self.git(self.d, "checkout", "-q", self.base)
        self.evil_merge()
        self.rename_and_change_then_delete()
        outcome = self.run_amend_with(
            [{"signature": s, "path_glob": "test/fixtures/*"} for s in signatures])
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.ever_holds(STAGE3))
        self.assertTrue(self.holds_at("samples", "test/fixtures/sample.js", STAGE3))

    def test_a_copy_left_for_manual_recovery_does_not_stop_the_rest(self):
        self.evil_merge()
        self.write(self.d, "src/boot.js", STAGE3)
        self.commit(self.d, "add boot")
        self.git(self.d, "mv", "src/boot.js", "docs/boot.md")
        self.commit(self.d, "move it")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertIn(Cause.PAYLOAD_NEEDS_MANUAL_RECOVERY, self._causes(outcome))
        self.assertFalse(self.holds(self.base, "vendor/x/loader.js"))
        self.assertTrue(self.holds(self.base, "docs/boot.md"))

    def test_a_copy_from_before_the_infection_does_not_stop_the_rest(self):
        self.write(self.d, "tools/s3.js", STAGE3)
        self.commit(self.d, "an old tool")
        self.git(self.d, "rm", "-q", "tools/s3.js")
        self.commit(self.d, "drop the old tool")
        self.evil_merge()
        self.write(self.d, "src/boot.js", STAGE3)
        self.commit(self.d, "add boot")
        self.git(self.d, "rm", "-q", "src/boot.js")
        self.commit(self.d, "drop boot")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self.holds(self.base, "vendor/x/loader.js"))
        rewritten = self.git(self.d, "log", "--format=%H", "--grep=add boot", self.base).split()
        self.assertFalse(self.holds(rewritten[0], "src/boot.js"))

    def test_commits_from_before_the_infection_are_not_rewritten(self):
        self.write(self.d, "tests/fixtures/old.js", STAGE3.replace("uname", "date"))
        before = self.commit(self.d, "test: an old sample")
        self.evil_merge()
        self.write(self.d, "tests/fixtures/old.js", STAGE2)
        self.commit(self.d, "test: refresh the sample")
        self.git(self.d, "rm", "-q", "tests/fixtures/old.js")
        self.commit(self.d, "test: drop the sample")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertIn(before, self.git(self.d, "rev-list", self.base).split())

    def test_injected_lines_in_an_older_version_are_cut_out_and_the_rest_stays(self):
        self.evil_merge()
        self.write(self.d, ".gitignore", "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n")
        self.commit(self.d, "markers added")
        self.write(self.d, ".gitignore", "node_modules\n")
        self.commit(self.d, "markers removed by hand")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        older = self.git(self.d, "show", f"{self.base}~1:.gitignore")
        self.assertIn("node_modules", older)
        self.assertNotIn("temp_auto_push.bat", older)

    def test_a_large_version_found_and_taken_out_is_not_counted_as_partly_read(self):
        self.evil_merge()
        self.write(self.d, "assets/big.js", "// " + "x" * 2_100_000 + "\n" + STAGE3)
        self.commit(self.d, "a large file with a payload at its end")
        self.git(self.d, "rm", "-q", "assets/big.js")
        self.commit(self.d, "drop it")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertNotIn(Cause.HISTORY_PARTLY_READ, self._causes(outcome))

    def test_versions_not_read_in_full_are_named(self):
        self.evil_merge()
        self.write(self.d, "assets/big.js", "// " + "x" * 2_100_000 + "\n")
        self.commit(self.d, "a large asset")
        self.write(self.d, "assets/big.js", "// " + "y" * 2_100_000 + "\n")
        self.commit(self.d, "the asset updated")
        outcome = self.run_amend()
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertIn(Cause.HISTORY_PARTLY_READ, self._causes(outcome))

if __name__ == "__main__":
    unittest.main()
