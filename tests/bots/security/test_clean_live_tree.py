#!/usr/bin/env python3
"""What a run does to the checkout the operator is standing in."""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.pr import held
from stayawake.bots.security.pr.fix_verdict import (
    BaseFix, BaseState, Checkout, FixVerdict, Remedy, checkout_of, render_fix_verdict)
from stayawake.bots.security.remediation import live, preserve
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.gitrepo import GitSandbox
from tests.support.scratchroot import OwnTempRoot

LOADER = "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n"


def _said(result, detail: bool = False) -> str:
    """What the operator is told about a checkout pass."""
    state, found = checkout_of(result)
    return render_fix_verdict(FixVerdict("p", BaseFix(BaseState.PREPARED, "p", "main"), state,
                                         checkout_detail=found), detail)
GENUINE_FONT = b"wOFF\x00\x01\x00\x00genuine third-party font bytes\n"


class _Checkout(OwnTempRoot):
    def setUp(self):
        super().setUp()
        self.root = (self.tmp / "project").resolve()
        (self.root / "public" / "fonts").mkdir(parents=True)
        (self.root / "src").mkdir()
        (self.root / "src" / "index.js").write_text("export const greet = (n) => n;\n")

    def _findings(self):
        return scan_target(LocalRepoTarget(self.root, "p", ScanOptions()),
                           load_signatures(), []).findings

    def _clean(self):
        return live.clean(self.root, self._findings(), load_signatures(), [], ScanOptions())


class TestThePayloadLeavesTheCheckout(_Checkout):
    def test_the_condemned_file_is_gone_from_the_checkout(self):
        payload = self.root / "public" / "fonts" / "text.woff"
        payload.write_text(LOADER)
        result = self._clean()
        self.assertFalse(payload.exists())
        self.assertIn("public/fonts/text.woff", result.removed)

    def test_no_copy_of_it_is_kept_anywhere_under_the_checkout(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        self._clean()
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn("fromCharCode", path.read_text(errors="replace"), str(path))

    def test_the_operators_other_files_are_untouched(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        self._clean()
        self.assertEqual("export const greet = (n) => n;\n",
                         (self.root / "src" / "index.js").read_text())

    def test_a_checkout_with_nothing_condemned_is_left_alone(self):
        before = sorted(str(p) for p in self.root.rglob("*"))
        result = self._clean()
        self.assertEqual([], result.removed)
        self.assertEqual(before, sorted(str(p) for p in self.root.rglob("*")))


class TestItNeverRemovesWhatItDidNotRead(_Checkout):
    """Check what a run does to a path it cannot read as a file."""

    def _condemn(self, path):
        from stayawake.bots.security.models import Finding, Severity
        return [Finding("x", "c", Severity.CRITICAL, path, "d",
                        remediation="remove-file", confidence="confirmed")]

    def test_a_directory_at_a_condemned_path_survives(self):
        here = self.root / "public" / "fonts" / "text.woff"
        here.mkdir(parents=True)
        (here / "theirs.md").write_text("mine\n")
        result = live.clean(self.root, self._condemn("public/fonts/text.woff"),
                            load_signatures(), [], ScanOptions())
        self.assertTrue((here / "theirs.md").exists())
        self.assertEqual([], result.removed)

    def test_a_run_that_met_one_is_not_complete(self):
        (self.root / "public" / "fonts" / "text.woff").mkdir(parents=True)
        result = live.clean(self.root, self._condemn("public/fonts/text.woff"),
                            load_signatures(), [], ScanOptions())
        self.assertFalse(result.complete)

    def test_a_payload_file_is_still_removed(self):
        payload = self.root / "public" / "fonts" / "text.woff"
        payload.write_text(LOADER)
        result = live.clean(self.root, self._findings(), load_signatures(), [], ScanOptions())
        self.assertFalse(payload.exists())
        self.assertEqual(["public/fonts/text.woff"], result.removed)


class TestARefusedRemovalIsNotCalledClean(_Checkout):
    """Check what a run says when it could not act on a condemned path."""

    def _redirected(self):
        outside = (self.tmp / "elsewhere" / "fonts")
        outside.mkdir(parents=True)
        (outside / "text.woff").write_text(LOADER)
        (self.root / "public" / "fonts").rmdir()
        (self.root / "public" / "fonts").symlink_to(outside)
        from stayawake.bots.security.models import Finding, Severity
        return [Finding("x", "c", Severity.CRITICAL, "public/fonts/text.woff", "d",
                        remediation="remove-file", confidence="confirmed")]

    def test_it_is_not_reported_as_no_longer_carrying(self):
        result = live.clean(self.root, self._redirected(), load_signatures(), [], ScanOptions())
        self.assertEqual([], result.removed)
        self.assertEqual(["public/fonts/text.woff"], result.refused)

    def test_the_run_is_not_complete(self):
        result = live.clean(self.root, self._redirected(), load_signatures(), [], ScanOptions())
        self.assertFalse(result.complete)


class TestItNamesPathsOnlyForAPerson(_Checkout):
    """Check what the note gives away to each audience."""

    def _unfinished(self):
        result = live.LiveResult()
        result.refused.append("public/fonts/text.woff")
        return live.CheckoutResult(confirmed=1, removed=result)

    def test_a_person_at_a_terminal_is_told_which_path(self):
        self.assertIn("public/fonts/text.woff", _said(self._unfinished(), detail=True))

    def test_an_automated_run_is_given_the_count_only(self):
        note = _said(self._unfinished())
        self.assertNotIn("public/fonts", note)
        self.assertIn("1 confirmed file(s) are still in it", note)


class TestItSaysWhatItCouldNotDo(_Checkout):
    def test_a_clean_run_is_complete(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        findings = self._findings()
        result = live.clean(self.root, findings, load_signatures(), [], ScanOptions())
        self.assertTrue(result.complete)
        self.assertEqual([], result.unread)

    def test_a_run_it_could_not_finish_is_not_complete(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        findings = self._findings()
        (self.root / "public" / "fonts").chmod(0o000)
        self.addCleanup((self.root / "public" / "fonts").chmod, 0o700)
        result = live.clean(self.root, findings, load_signatures(), [], ScanOptions())
        self.assertFalse(result.complete)
        self.assertIn("not read in full", _said(live.CheckoutResult(confirmed=1, removed=result)))

    def test_a_path_already_gone_does_not_make_the_run_unfinished(self):
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        findings = self._findings()
        (self.root / "public" / "fonts" / "text.woff").unlink()
        result = live.clean(self.root, findings, load_signatures(), [], ScanOptions())
        self.assertTrue(result.complete)
        self.assertIn("public/fonts/text.woff", result.absent)

    def test_what_it_did_not_remove_is_named(self):
        payload = self.root / "public" / "fonts" / "text.woff"
        payload.write_text(LOADER)
        findings = self._findings()
        payload.chmod(0o000)
        (self.root / "public" / "fonts").chmod(0o500)
        self.addCleanup(lambda: ((self.root / "public" / "fonts").chmod(0o700),
                                 payload.chmod(0o600) if payload.exists() else None))
        result = live.clean(self.root, findings, load_signatures(), [], ScanOptions())
        self.assertIn("public/fonts/text.woff", result.unfinished)


class TestARewriteBetweenTheTwoReadsDoesNotSaveIt(_Checkout):
    """Check what happens when the condemned bytes change after the scan."""

    def _condemned_then_rewritten(self, replacement: bytes):
        payload = self.root / "public" / "fonts" / "text.woff"
        payload.write_text(LOADER)
        findings = self._findings()
        payload.write_bytes(replacement)
        return payload, live.clean(self.root, findings, load_signatures(), [], ScanOptions())

    def test_the_file_is_still_removed(self):
        payload, result = self._condemned_then_rewritten(GENUINE_FONT)
        self.assertFalse(payload.exists())
        self.assertIn("public/fonts/text.woff", result.removed)

    def test_a_rewrite_that_no_longer_confirms_does_not_make_the_run_clean_of_it(self):
        payload, result = self._condemned_then_rewritten(b"var x = 1;\n")
        self.assertFalse(payload.exists())

    def test_the_run_is_complete_because_it_acted(self):
        _, result = self._condemned_then_rewritten(GENUINE_FONT)
        self.assertTrue(result.complete)


class TestAConfirmedFindingNoRemovalCanExpress(GitSandbox):
    """Check a checkout whose confirmed finding is repaired rather than unlinked."""

    def setUp(self):
        super().setUp()
        self.root = self.new_repo("project")
        self.write(self.root, "src/index.js", "export const greet = (n) => n;\n")
        self.commit(self.root, "a starting point")
        (self.root / ".vscode").mkdir(parents=True)
        (self.root / ".vscode" / "settings.json").write_text(
            '{\n  // our ADR-14 says keep this\n  "editor.rulers": [100],\n'
            '  "task.allowAutomaticTasks": "on"\n}\n')
        (self.root / "notes.md").write_text("my own work\n")

    def _checkout(self):
        def scan(*_a, **_k):
            return scan_target(LocalRepoTarget(self.root, "p", ScanOptions()),
                               load_signatures(), [])
        return live.clean_checkout(self.root, ScanOptions(), load_signatures(), [], scan=scan)

    def test_what_was_found_is_taken_out_of_the_file(self):
        result = self._checkout()
        self.assertTrue(result.infected, "the fixture must carry a confirmed finding")
        self.assertNotIn("allowAutomaticTasks",
                         (self.root / ".vscode" / "settings.json").read_text())
        self.assertIn(".vscode/settings.json", result.removed.stripped)

    def test_the_rest_of_their_file_is_left_exactly_as_it_was(self):
        self._checkout()
        text = (self.root / ".vscode" / "settings.json").read_text()
        self.assertIn("// our ADR-14 says keep this", text)
        self.assertIn('"editor.rulers": [100]', text)

    def test_the_run_is_complete_because_it_acted(self):
        self.assertTrue(self._checkout().complete)

    def test_the_operator_is_told_it_acted(self):
        self.assertIn("took what was found out of", _said(self._checkout()))

    def test_the_operators_own_file_is_untouched(self):
        self._checkout()
        self.assertEqual("my own work\n", (self.root / "notes.md").read_text())


class TestAWorkingTreeGitCannotListIsNotClearedInBulk(GitSandbox):
    """Check what a run does when the operator's work cannot be held."""

    def setUp(self):
        super().setUp()
        self.root = self.new_repo("project")
        self.write(self.root, "src/index.js", "export const greet = (n) => n;\n")
        self.write(self.root, "package-lock.json", '{"lockfileVersion": 3, "packages": {"": {}}}\n')
        self.commit(self.root, "a starting point")
        (self.root / "public" / "fonts").mkdir(parents=True)
        (self.root / "public" / "fonts" / "text.woff").write_text(LOADER)
        (self.root / "dist").mkdir()
        (self.root / "dist" / "only-copy.js").write_text("built v2\n")

    def _checkout(self):
        def scan(*_a, **_k):
            return scan_target(LocalRepoTarget(self.root, "p", ScanOptions()),
                               load_signatures(), [])
        with mock.patch.object(live.preserve, "can_hold",
                               return_value="git could not list the working tree (rc 128)"):
            return live.clean_checkout(self.root, ScanOptions(), load_signatures(), [], scan=scan)

    def test_the_confirmed_file_still_goes(self):
        self._checkout()
        self.assertFalse((self.root / "public" / "fonts" / "text.woff").exists())

    def test_the_generated_tree_and_lockfile_are_left(self):
        self._checkout()
        self.assertTrue((self.root / "dist" / "only-copy.js").is_file())
        self.assertTrue((self.root / "package-lock.json").is_file())

    def test_the_run_says_why_and_is_not_complete(self):
        result = self._checkout()
        self.assertFalse(result.complete)
        self.assertIn("could not be held", _said(result))


class TestARunThatChangedNothingMakesNoBranch(GitSandbox):
    """Check what a run leaves when the checkout had nothing for it to do."""

    def test_no_branch_is_made(self):
        root = self.new_repo("project")
        self.write(root, "src/index.js", "export const greet = (n) => n;\n")
        self.commit(root, "a starting point")
        (root / "notes.md").write_text("my own work\n")

        def scan(*_a, **_k):
            return scan_target(LocalRepoTarget(root, "p", ScanOptions()), load_signatures(), [])
        result = live.clean_checkout(root, ScanOptions(), load_signatures(), [], scan=scan,
                                     base_confirmed=True)
        self.assertEqual("", result.kept.branch)
        self.assertEqual("", self.git(root, "for-each-ref", "refs/heads/saw/").strip())


class TestWhatMakesARunIncomplete(unittest.TestCase):
    """Check each thing that must stop a run being called clean."""

    def test_nothing_to_branch_from_is_not_a_failure(self):
        self.assertTrue(live.CheckoutResult(
            kept=preserve.Preserved(reason="this repository has no commit to branch from")).complete)

    def test_a_preservation_that_failed_outright(self):
        result = live.CheckoutResult(
            confirmed=1,
            kept=preserve.Preserved(reason="the working tree could not be staged",
                                    blocked=True))
        self.assertFalse(result.complete)

    def test_a_confirmed_path_it_did_not_clear(self):
        self.assertFalse(live.CheckoutResult(confirmed=1, left_alone=["a.js"]).complete)

    def test_a_checkout_it_could_not_read(self):
        self.assertFalse(live.CheckoutResult(scan_error="not read in full").complete)

    def test_an_installed_tree_it_could_not_remove(self):
        self.assertFalse(live.CheckoutResult(confirmed=1, failure="could not remove").complete)

    def test_a_tree_the_remover_could_not_take(self):
        from stayawake.bots.security.remediation import installed
        report = installed.Report()
        report.not_removed.append(Path("dist"))
        self.assertFalse(live.CheckoutResult(confirmed=1, report=report).complete)

    def test_a_confirmed_file_still_staged(self):
        self.assertFalse(live.CheckoutResult(confirmed=1, staged=["a.woff"]).complete)

    def test_a_confirmed_file_git_could_not_list(self):
        self.assertFalse(live.CheckoutResult(confirmed=1, index_unread="no").complete)

    def test_a_confirmed_file_only_the_history_holds_is_not_the_checkouts(self):
        self.assertTrue(live.CheckoutResult(confirmed=1, cleared=["a.woff"]).complete)

    def test_a_run_with_none_of_those_is_complete(self):
        self.assertTrue(live.CheckoutResult().complete)


class TestTheSavedBranchHoldsOnlyTheOperatorsWork(GitSandbox):
    """Check what the saved branch records for a path the run removed."""

    LOADER = 'var _0x=String.fromCharCode(118,97,114);eval(_0x+" x=1");\n'

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("work", user__name="Tester")
        self.write(self.repo, "package.json", '{"name": "app", "version": "1.0.0"}\n')
        self.write(self.repo, "dist/app.js", "v1\n")
        self.commit(self.repo, "init")
        self.write(self.repo, "dist/app.js", "v2\n")
        self.write(self.repo, "notes.md", "mine\n")
        self.write(self.repo, "public/fonts/text.woff", self.LOADER)

    def _run(self):
        return live.clean_checkout(self.repo, ScanOptions(), load_signatures(), []).kept

    def test_a_removed_path_is_not_recorded_as_deleted_on_the_branch(self):
        kept = self._run()
        changes = self.git(self.repo, "diff", "--name-status", "HEAD", kept.branch).split()
        self.assertEqual(["A", "notes.md"], changes)

    def test_the_count_is_the_files_whose_content_is_on_the_branch(self):
        self.assertEqual(1, self._run().files)


class TestAWorkingTreeGitCannotListDoesNotStopTheReport(TestTheSavedBranchHoldsOnlyTheOperatorsWork):
    """Check the run when git cannot list the working tree, before or after the removal."""

    def _result(self, fail_on):
        real, calls = live.preserve.uncommitted, []

        def listing(repo):
            calls.append(repo)
            if len(calls) in fail_on:
                raise live.preserve.WorkingTreeUnlisted("status failed")
            return real(repo)

        with mock.patch.object(live.preserve, "uncommitted", listing):
            return live.clean_checkout(self.repo, ScanOptions(), load_signatures(), [])

    def test_a_listing_that_fails_after_the_removal_is_reported(self):
        result = self._result({2})
        self.assertTrue(result.kept.blocked)
        self.assertIn("could not list", result.kept.reason)

    def test_a_listing_that_fails_before_it_leaves_the_installed_tree(self):
        result = self._result({1})
        self.assertIsNone(result.report)
        self.assertIn("could not be held", result.failure)


class TestAStrippedFileIsNotRecordedAsDeleted(GitSandbox):
    """Check what the saved branch records for a tracked file the run edited in place."""

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("strip", user__name="Tester")
        self.write(self.repo, ".vscode/settings.json",
                   '{\n  "editor.tabSize": 2,\n  "task.allowAutomaticTasks": "on"\n}\n')
        self.write(self.repo, "src/index.js", "a\n")
        self.commit(self.repo, "init")
        self.write(self.repo, "src/index.js", "b\n")

    def test_the_branch_holds_the_cleaned_file_as_it_now_stands(self):
        kept = live.clean_checkout(self.repo, ScanOptions(), load_signatures(), []).kept
        changes = self.git(self.repo, "diff", "--name-status", "HEAD", kept.branch).split()
        self.assertEqual(["M", ".vscode/settings.json", "M", "src/index.js"], changes)
        saved = self.git(self.repo, "show", f"{kept.branch}:.vscode/settings.json")
        self.assertIn('"editor.tabSize": 2', saved)
        self.assertNotIn("allowAutomaticTasks", saved)


class TestARefusedEditIsReportedOnce(GitSandbox):
    """Check how a settings edit saw would not write is reported."""

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("refused", user__name="Tester")
        self.write(self.repo, ".vscode/settings.json",
                   '{\n  "editor.tabSize": 2,\n  "task.allowAutomaticTasks": "on"\n}\n')
        self.commit(self.repo, "init")

    def test_it_is_named_once_and_the_run_is_not_clean(self):
        from stayawake.bots.security.remediation import changes
        with mock.patch.object(changes, "_keeps_the_rest", return_value=False), \
                mock.patch.object(changes, "_rewritten_without_autorun", side_effect=lambda t: t):
            result = live.clean_checkout(self.repo, ScanOptions(), load_signatures(), [])
        self.assertIn(".vscode/settings.json", result.removed.unfinished)
        self.assertNotIn(".vscode/settings.json", result.left_alone)
        self.assertEqual(1, _said(result, detail=True).count(".vscode/settings.json"))
        self.assertFalse(result.complete)


class _LiveRepo(GitSandbox):
    """A committed repository and a run over its live checkout."""

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("live", user__name="Tester")
        self.write(self.repo, "README.md", "readme\n")
        self.write(self.repo, "src/app.js", "module.exports = 1;\n")
        self.commit(self.repo, "init")

    def run_fix(self, keep=()):
        return live.clean_checkout(self.repo, ScanOptions(), load_signatures(), [], keep=keep)

    def tree(self, ref):
        return self.git(self.repo, "ls-tree", "-r", "--name-only", ref).splitlines()


class TestAKeptDirectoryIsReadWhateverItsDepth(_LiveRepo):
    """Check that a kept directory an exclusion would hide is still read."""

    def _payload_at(self, rel):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.write(self.repo, rel, LOADER)

    def test_one_under_an_excluded_name(self):
        self._payload_at("packages/a/node_modules/evil/text.woff")
        result = self.run_fix(keep=("packages/a/node_modules",))
        self.assertFalse((self.repo / "packages/a/node_modules/evil/text.woff").exists())
        self.assertEqual(2, result.confirmed)

    def test_one_holding_an_excluded_name(self):
        self._payload_at("packages/a/node_modules/evil/text.woff")
        result = self.run_fix(keep=("packages/a",))
        self.assertFalse((self.repo / "packages/a/node_modules/evil/text.woff").exists())
        self.assertEqual(2, result.confirmed)


class TestWhatTheScanLeavesOutIsReadOnceInfected(_LiveRepo):
    """Check directories the scan leaves out by name, below the root, on a confirmed infection."""

    def test_a_payload_in_a_nested_output_directory_is_removed(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.write(self.repo, "packages/app/dist/text.woff", LOADER)
        result = self.run_fix()
        self.assertFalse((self.repo / "packages/app/dist/text.woff").exists())
        self.assertEqual(2, result.confirmed)
        self.assertTrue(result.complete)

    def test_a_payload_in_a_directory_the_operator_leaves_out_is_removed(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.write(self.repo, ".venv/lib/text.woff", LOADER)
        opts = ScanOptions(exclude_dirs=ScanOptions().exclude_dirs | {".venv"})
        live.clean_checkout(self.repo, opts, load_signatures(), [])
        self.assertFalse((self.repo / ".venv/lib/text.woff").exists())


class TestADirectoryNamedLikeSawsOwnBelowTheRoot(_LiveRepo):
    """Check a directory called `.saw` that is not saw's own."""

    def test_its_payload_is_read_and_removed(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.write(self.repo, "src/.saw/q.woff", LOADER)
        result = self.run_fix()
        self.assertFalse((self.repo / "src" / ".saw" / "q.woff").exists())
        self.assertEqual(2, result.confirmed)

    def test_one_inside_an_output_directory_is_read_too(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.write(self.repo, "packages/app/dist/.saw/q.woff", LOADER)
        self.run_fix()
        self.assertFalse((self.repo / "packages/app/dist/.saw/q.woff").exists())


class TestAPayloadOnlyWhereTheScanLeavesOut(_LiveRepo):
    """Check a checkout whose only payload sits in a directory the scan leaves out by name."""

    def test_it_is_found_and_removed(self):
        self.write(self.repo, "dist/text.woff", LOADER)
        result = self.run_fix()
        self.assertEqual(1, result.confirmed)
        self.assertFalse((self.repo / "dist" / "text.woff").exists())


class TestTheBytesOfARemovedPayloadStayOutOfGit(_LiveRepo):
    """Check a file holding the same bytes as a confirmed payload under another name."""

    def test_they_are_not_saved_under_the_other_name(self):
        self.write(self.repo, "public/p.woff", LOADER)
        self.write(self.repo, "scripts/setup.js", LOADER)
        self.write(self.repo, "notes.md", "mine\n")
        kept = self.run_fix().kept
        self.assertTrue(kept.branch)
        self.assertNotIn("scripts/setup.js", self.tree(kept.branch))
        self.assertTrue((self.repo / "scripts" / "setup.js").exists())
        oid = subprocess.run(["git", "hash-object", "--stdin"], input=LOADER, text=True,
                             check=True, capture_output=True).stdout.strip()
        stored = subprocess.run(["git", "-C", str(self.repo), "cat-file", "-e", oid],
                                capture_output=True)
        self.assertNotEqual(0, stored.returncode)


class TestACommittedPayloadNoLongerOnDisk(_LiveRepo):
    """Check a payload the current commit holds while the file on disk is gone or changed."""

    def _committed_then(self, on_disk):
        self.git(self.repo, "checkout", "-qb", "feature")
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.commit(self.repo, "payload")
        if on_disk is None:
            os.remove(self.repo / "fonts" / "text.woff")
        else:
            (self.repo / "fonts" / "text.woff").write_bytes(on_disk)
        return self.run_fix()

    def _holds(self, result):
        history = held.history_holds(self.repo, result.cleared, "main", load_signatures(), [],
                                     ScanOptions())
        return [(h.where, h.name, h.remedy) for h in history.holds]

    def test_a_deleted_one_is_reported_as_held_by_the_commit(self):
        result = self._committed_then(None)
        self.assertEqual(["fonts/text.woff"], result.cleared)
        self.assertEqual([("head", "feature", Remedy.AMEND)], self._holds(result))

    def test_one_whose_deletion_is_staged_is_reported_too(self):
        self._committed_then(None)
        self.git(self.repo, "rm", "-q", "--cached", "fonts/text.woff")
        result = self.run_fix()
        self.assertEqual([("head", "feature", Remedy.AMEND)], self._holds(result))

    def test_one_replaced_by_a_staged_clean_file_is_reported_too(self):
        self._committed_then(GENUINE_FONT)
        self.git(self.repo, "add", "fonts/text.woff")
        result = self.run_fix()
        self.assertEqual([("head", "feature", Remedy.AMEND)], self._holds(result))

    def test_one_edited_clean_is_reported_too(self):
        result = self._committed_then(GENUINE_FONT)
        self.assertEqual([("head", "feature", Remedy.AMEND)], self._holds(result))
        self.assertEqual(GENUINE_FONT, (self.repo / "fonts" / "text.woff").read_bytes())


class TestACopyOfAPayloadRemovedWithItsTree(_LiveRepo):
    """Check copies of a payload the run removed from a generated tree or through a link."""

    def _object_stored(self, text):
        oid = subprocess.run(["git", "hash-object", "--stdin"], input=text, text=True,
                             check=True, capture_output=True).stdout.strip()
        return subprocess.run(["git", "-C", str(self.repo), "cat-file", "-e", oid],
                              capture_output=True).returncode == 0

    def test_a_copy_of_one_in_a_removed_output_directory_stays_out_of_git(self):
        self.write(self.repo, "dist/text.woff", LOADER)
        self.write(self.repo, "src/copy.js", LOADER)
        self.write(self.repo, "notes.md", "mine\n")
        kept = self.run_fix().kept
        self.assertTrue(kept.branch)
        self.assertFalse(self._object_stored(LOADER))

    def test_a_copy_of_one_only_staged_stays_out_of_git(self):
        self.write(self.repo, "public/text.woff", LOADER)
        self.git(self.repo, "add", "public/text.woff")
        (self.repo / "public" / "text.woff").write_bytes(GENUINE_FONT)
        self.write(self.repo, "notes/copy.js", LOADER)
        self.write(self.repo, "notes.md", "mine\n")
        self.write(self.repo, "node_modules/left-pad/index.js", "module.exports = 1;\n")
        result = self.run_fix()
        self.assertEqual(["public/text.woff"], result.unstaged)
        self.assertTrue(result.kept.branch)
        self.assertNotIn("notes/copy.js", self.tree(result.kept.branch))

    def test_the_file_a_confirmed_link_reads_as_stays_out_of_git(self):
        self.write(self.repo, "src/loader.js", LOADER)
        (self.repo / "fonts").mkdir()
        os.symlink("../src/loader.js", self.repo / "fonts" / "text.woff")
        self.write(self.repo, "notes.md", "mine\n")
        kept = self.run_fix().kept
        self.assertTrue(kept.branch)
        self.assertFalse(self._object_stored(LOADER))


class TestADirectoryReadJudgesContentOnly(_LiveRepo):
    """Check what reading a directory the scan leaves out asks of the scanner."""

    def test_it_runs_no_repository_wide_matcher_or_note(self):
        self.write(self.repo, "packages/a/dist/index.js", "module.exports = 1;\n")
        asked = []

        def scan(target, signatures, allowlist):
            if getattr(target, "within", None):
                asked.append(set(signatures))
                self.assertFalse(getattr(target, "is_repo", True))
            return scan_target(target, signatures, allowlist)
        live.clean_checkout(self.repo, ScanOptions(), load_signatures(), [], scan=scan)
        self.assertTrue(asked)
        for groups in asked:
            self.assertFalse(groups & {"git-history", "dependency-audit",
                                       "installed-package-audit"})


class TestOneBlobAtTwoPaths(_LiveRepo):
    """Check bytes git stores at a path where they confirm and at one where they do not."""

    def test_the_path_where_they_confirm_is_taken_out(self):
        self.write(self.repo, "a/copy.js", LOADER)
        self.write(self.repo, "b/x.woff", LOADER)
        self.git(self.repo, "add", "a/copy.js", "b/x.woff")
        os.remove(self.repo / "a" / "copy.js")
        os.remove(self.repo / "b" / "x.woff")
        result = self.run_fix()
        self.assertEqual(["b/x.woff"], result.unstaged)
        self.assertEqual("", self.git(self.repo, "ls-files", "-s", "--", "b/x.woff"))


class TestAPathThatIsNotUtf8(_LiveRepo):
    """Check a payload git's index holds under a name that is not valid UTF-8."""

    def _index(self):
        return subprocess.run(["git", "-C", str(self.repo), "ls-files", "-s", "-z"],
                              capture_output=True, check=True).stdout

    def _held_at(self, name: bytes):
        oid = subprocess.run(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
                             input=LOADER.encode(), capture_output=True,
                             check=True).stdout.strip()
        subprocess.run(["git", "-C", str(self.repo), "update-index", "--add", "--cacheinfo",
                        b"100644," + oid + b"," + name], check=True, capture_output=True)

    def test_a_staged_one_leaves_the_index(self):
        self._held_at(b"public/x\xff.woff")
        self.run_fix()
        self.assertNotIn(b"x\xff.woff", self._index())

    def test_a_committed_one_is_named_to_the_history(self):
        self._held_at(b"public/x\xff.woff")
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "payload"], check=True,
                       capture_output=True)
        result = self.run_fix()
        self.assertEqual(["public/x\udcff.woff"], result.cleared)


class TestACommittedPayloadTheRunRemoved(_LiveRepo):
    """Check the saved branch where the current commit holds a payload the run's removals reached."""

    def test_it_is_not_on_the_saved_branch(self):
        self.write(self.repo, "dist/x.woff", LOADER)
        self.commit(self.repo, "build output")
        (self.repo / "dist" / "x.woff").write_bytes(GENUINE_FONT)
        self.write(self.repo, "src/app.js", "module.exports = 2;\n")
        self.write(self.repo, "fonts/t.woff", LOADER)
        kept = self.run_fix().kept
        self.assertTrue(kept.branch)
        self.assertNotIn("dist/x.woff", self.tree(kept.branch))


class TestAStagedRenameThatChangesOnlyLetterCase(_LiveRepo):
    """Check a committed payload staged under a name differing only in letter case."""

    def test_the_staged_copy_is_taken_out(self):
        self.write(self.repo, "fonts/a.woff", LOADER)
        self.commit(self.repo, "payload")
        self.git(self.repo, "mv", "-f", "fonts/a.woff", "fonts/A.woff")
        (self.repo / "fonts" / "A.woff").write_bytes(GENUINE_FONT)
        result = self.run_fix()
        self.assertEqual("", self.git(self.repo, "ls-files", "-s", "--", "fonts/A.woff"))
        self.assertIn("fonts/A.woff", result.unstaged)


class TestAPayloadCommittedInsideAnInstalledTree(_LiveRepo):
    """Check a payload the current commit holds inside a tree the run removes whole."""

    def test_it_is_named_and_kept_off_the_saved_branch(self):
        self.write(self.repo, "node_modules/pkg/f.woff", LOADER)
        self.commit(self.repo, "vendored")
        self.write(self.repo, "src/app.js", "module.exports = 2;\n")
        self.write(self.repo, "fonts/t.woff", LOADER)
        result = self.run_fix()
        self.assertFalse((self.repo / "node_modules").exists())
        self.assertIn("node_modules/pkg/f.woff", result.cleared)
        self.assertTrue(result.kept.branch)
        self.assertNotIn("node_modules/pkg/f.woff", self.tree(result.kept.branch))


class TestAPayloadOnlyInTheStagedChanges(_LiveRepo):
    """Check a payload git's index holds while the disk does not."""

    def _staged_then_replaced(self, on_disk):
        self.write(self.repo, "lib/evil.woff", LOADER)
        self.git(self.repo, "add", "lib/evil.woff")
        if on_disk is None:
            os.remove(self.repo / "lib" / "evil.woff")
        else:
            (self.repo / "lib" / "evil.woff").write_bytes(on_disk)

    def test_it_is_found_and_taken_out_of_the_index(self):
        self._staged_then_replaced(None)
        result = self.run_fix()
        self.assertEqual(1, result.confirmed)
        self.assertEqual("", self.git(self.repo, "ls-files", "-s", "--", "lib/evil.woff"))
        self.assertTrue(result.complete)

    def test_a_clean_file_on_disk_at_that_path_stays(self):
        self._staged_then_replaced(GENUINE_FONT)
        self.run_fix()
        self.assertEqual(GENUINE_FONT, (self.repo / "lib" / "evil.woff").read_bytes())
        self.assertEqual("", self.git(self.repo, "ls-files", "-s", "--", "lib/evil.woff"))


class TestALinkNamedLikeAnotherKindOfFile(_LiveRepo):
    """Check a confirmed link whose target is an ordinary file of the repository."""

    def test_the_link_goes_and_the_file_it_points_at_stays(self):
        source = "".join(f"function handler{i}(req, res) {{\n  return res.json({{ ok: true }});\n}}\n"
                         for i in range(20))
        self.write(self.repo, "src/index.js", source)
        self.commit(self.repo, "source")
        self.write(self.repo, "src/index.js", source + "module.exports.extra = 42;\n")
        (self.repo / "assets").mkdir()
        os.symlink("../src/index.js", self.repo / "assets" / "logo.png")
        result = self.run_fix()
        self.assertEqual(1, result.confirmed)
        self.assertFalse(os.path.lexists(self.repo / "assets" / "logo.png"))
        self.assertTrue((self.repo / "src" / "index.js").read_text().endswith("extra = 42;\n"))


class TestAConfirmedLinkIsNeverWrittenIntoGit(_LiveRepo):
    """Check what the saved branch does with a confirmed link the run leaves for review."""

    def test_its_target_is_not_stored(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        target = "../" * 12 + os.path.expanduser("~").lstrip("/") + "/.ssh/authorized_keys"
        os.symlink(target, self.repo / "hook_link")
        self.write(self.repo, "src/app.js", "module.exports = 2;\n")
        result = self.run_fix()
        self.assertIn("hook_link", result.left_alone)
        oid = subprocess.run(["git", "hash-object", "--stdin"], input=target, text=True,
                             check=True, capture_output=True).stdout.strip()
        stored = subprocess.run(["git", "-C", str(self.repo), "cat-file", "-e", oid],
                                capture_output=True)
        self.assertNotEqual(0, stored.returncode)


class TestAPathIsNeverReadAsAPattern(_LiveRepo):
    """Check that a path spelled like git pattern syntax is handled as that path."""

    def test_a_committed_payload_named_like_a_pattern_is_not_on_the_branch(self):
        self.write(self.repo, ":fonts/text.woff", LOADER)
        self.write(self.repo, "fonts/keep.txt", "keep\n")
        self.commit(self.repo, "payload")
        self.write(self.repo, "README.md", "edited\n")
        kept = self.run_fix().kept
        self.assertTrue(kept.branch)
        self.assertNotIn(":fonts/text.woff", self.tree(kept.branch))

    def test_an_exclusion_shaped_name_does_not_empty_the_branch(self):
        self.write(self.repo, "README.md", "edited\n")
        self.write(self.repo, "src/app.js", "module.exports = 2;\n")
        self.write(self.repo, ":!fonts/text.woff", LOADER)
        kept = self.run_fix().kept
        self.assertEqual(["README.md", "src/app.js"], sorted(self.tree(kept.branch)))
        self.assertEqual(2, kept.files)


class TestAPartialReadStillActs(_LiveRepo):
    """Check a checkout with a directory the scan cannot read."""

    def setUp(self):
        super().setUp()
        locked = self.repo / "locked"
        locked.mkdir()
        (locked / "f.txt").write_text("x\n")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o755)

    def test_a_confirmed_payload_is_removed_and_the_checkout_is_not_called_clean(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        result = self.run_fix()
        self.assertFalse((self.repo / "fonts" / "text.woff").exists())
        self.assertTrue(result.scan_error)
        self.assertFalse(result.complete)

    def test_the_installed_tree_waits_for_a_full_read_and_the_work_is_saved(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.write(self.repo, "node_modules/pkg/index.js", "module.exports = 1;\n")
        self.write(self.repo, "src/app.js", "module.exports = 2;\n")
        result = self.run_fix()
        self.assertTrue((self.repo / "node_modules" / "pkg" / "index.js").exists())
        self.assertIn("not read in full", result.failure)
        self.assertTrue(result.kept.branch)


class TestWhatAGeneratedTreeHeldIsNotSaidToStay(_LiveRepo):
    """Check the note about uncommitted work inside a generated directory the run cleared."""

    def test_the_note_does_not_say_it_stays_on_disk(self):
        self.write(self.repo, "build/deploy.sh", "echo 1\n")
        self.commit(self.repo, "build script")
        self.write(self.repo, "build/deploy.sh", "echo 2\n")
        self.write(self.repo, "notes.md", "mine\n")
        self.write(self.repo, "fonts/text.woff", LOADER)
        result = self.run_fix()
        self.assertFalse((self.repo / "build").exists())
        self.assertNotIn("stay on disk", result.kept.note())


class TestWhatGitStillHoldsIsNotCalledClean(_LiveRepo):
    """Check a confirmed file git still holds after it left the working tree."""

    def _fed(self, args, text: str) -> str:
        return subprocess.run(["git", "-C", str(self.repo), *args], input=text, text=True,
                              check=True, capture_output=True).stdout

    def test_a_git_add_racing_the_rewrite_fails_rather_than_being_undone(self):
        from stayawake.lib.git.write import working_tree
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.git(self.repo, "add", "fonts/text.woff")
        self.write(self.repo, "other.js", "mine\n")
        raced = []
        real = working_tree.shutil.copyfile

        def copy_then_race(src, dst):
            out = real(src, dst)
            if not raced:
                raced.append(subprocess.run(["git", "-C", str(self.repo), "add", "other.js"],
                                            capture_output=True).returncode)
            return out
        with mock.patch.object(working_tree.shutil, "copyfile", side_effect=copy_then_race):
            self.run_fix()
        listed = self.git(self.repo, "ls-files", "--", "other.js")
        self.assertTrue(raced[0] != 0 or "other.js" in listed,
                        "work staged during the rewrite was silently undone")

    def test_a_staged_payload_under_another_letter_case_is_taken_out(self):
        folds = subprocess.run(["git", "-C", str(self.repo), "config", "--get", "core.ignorecase"],
                               capture_output=True, text=True).stdout.strip() == "true"
        if not folds:
            self.skipTest("this filesystem tells letter case apart")
        (self.repo / "fonts").mkdir(exist_ok=True)
        (self.repo / "fonts" / "Text.woff").write_bytes(GENUINE_FONT)
        self.git(self.repo, "add", "fonts/Text.woff")
        self.git(self.repo, "commit", "-qm", "font")
        (self.repo / "fonts" / "Text.woff").write_text(LOADER)
        self.git(self.repo, "add", "fonts/Text.woff")
        os.rename(self.repo / "fonts" / "Text.woff", self.repo / "fonts" / "tmp.woff")
        os.rename(self.repo / "fonts" / "tmp.woff", self.repo / "fonts" / "text.woff")
        self.run_fix()
        staged = self.git(self.repo, "ls-files", "-s", "--", "fonts/Text.woff")
        evil = self._fed(["hash-object", "--stdin"], LOADER).strip()
        self.assertNotIn(evil, staged)

    def test_a_staged_payload_is_taken_out_of_the_staged_changes(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.git(self.repo, "add", "fonts/text.woff")
        result = self.run_fix()
        self.assertEqual([], result.staged)
        self.assertEqual(["fonts/text.woff"], result.unstaged)
        self.assertEqual("", self.git(self.repo, "ls-files", "--", "fonts/text.woff"))
        self.assertIs(Checkout.CLEANED, checkout_of(result)[0])
        self.assertIn("took 1 confirmed file(s) out of your staged changes", _said(result))

    def _font_committed(self) -> str:
        (self.repo / "fonts").mkdir(exist_ok=True)
        (self.repo / "fonts" / "text.woff").write_bytes(GENUINE_FONT)
        self.git(self.repo, "add", "fonts/text.woff")
        self.git(self.repo, "commit", "-qm", "font")
        return self.git(self.repo, "rev-parse", "HEAD:fonts/text.woff").strip()

    def test_a_staged_payload_over_a_clean_file_goes_back_to_the_commit(self):
        committed = self._font_committed()
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.git(self.repo, "add", "fonts/text.woff")
        self.write(self.repo, "README.md", "my staged work\n")
        self.git(self.repo, "add", "README.md")
        self.run_fix()
        self.assertIn(committed, self.git(self.repo, "ls-files", "-s", "--", "fonts/text.woff"))
        self.assertIn("M  README.md", self.git(self.repo, "status", "--porcelain"))

    def test_a_conflict_keeps_its_clean_stages_and_stays_unresolved(self):
        base = self._font_committed()
        ours = self._fed(["hash-object", "-w", "--stdin"], "wOFF another genuine font\n").strip()
        evil = self._fed(["hash-object", "-w", "--stdin"], LOADER).strip()
        path = "fonts/text.woff"
        feed = (f"0 {'0' * 40}\t{path}\n100644 {base} 1\t{path}\n"
                f"100644 {ours} 2\t{path}\n100644 {evil} 3\t{path}\n")
        self._fed(["update-index", "--index-info"], feed)
        self.write(self.repo, path, LOADER)
        self.run_fix()
        stages = self.git(self.repo, "ls-files", "-s", "--", path)
        self.assertIn(ours, stages)
        self.assertNotIn(evil, stages)
        self.assertIn(f" 2\t{path}", stages)

    def test_a_payload_committed_on_the_branch(self):
        self.git(self.repo, "checkout", "-qb", "feature")
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.commit(self.repo, "payload")
        result = self.run_fix()
        self.assertEqual(["fonts/text.woff"], result.cleared)
        self.assertIs(Checkout.CLEANED, checkout_of(result)[0])
        history = held.history_holds(self.repo, result.cleared, "main", load_signatures(), [],
                                     ScanOptions())
        self.assertEqual([("head", "feature", Remedy.AMEND)],
                         [(h.where, h.name, h.remedy) for h in history.holds])

    def test_a_payload_in_any_stage_of_a_conflict(self):
        self.write(self.repo, "fonts/clean.txt", "clean\n")
        clean = self.git(self.repo, "hash-object", "-w", "fonts/clean.txt").strip()
        self.write(self.repo, "fonts/text.woff", LOADER)
        payload = self.git(self.repo, "hash-object", "-w", "fonts/text.woff").strip()
        subprocess.run(["git", "-C", str(self.repo), "update-index", "--index-info"], check=True,
                       input=f"100644 {payload} 2\tfonts/text.woff\n"
                             f"100644 {clean} 3\tfonts/text.woff\n", text=True)
        result = self.run_fix()
        self.assertEqual([], result.staged)
        self.assertEqual(["fonts/text.woff"], result.unstaged)
        stages = self.git(self.repo, "ls-files", "-s", "--", "fonts/text.woff")
        self.assertNotIn(payload, stages)
        self.assertIn(f"{clean} 3", stages)

    def test_an_untracked_payload_leaves_git_holding_nothing(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        result = self.run_fix()
        self.assertEqual([], result.staged)
        self.assertTrue(result.complete)
        self.assertEqual((), held.history_holds(self.repo, result.cleared, "main",
                                                load_signatures(), [], ScanOptions()).holds)

    def test_a_listing_git_refuses_is_not_read_as_nothing_held(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        real = live.stdout_bytes_fed

        def refusing(repo, args, stdin, **kw):
            return None if args[0] in ("ls-files", "ls-tree") else real(repo, args, stdin, **kw)
        with mock.patch.object(live, "stdout_bytes_fed", refusing):
            result = self.run_fix()
        self.assertFalse(result.complete)
        self.assertIs(Checkout.UNREAD, checkout_of(result)[0])
        self.assertIn("git could not say what its index holds", _said(result))


class TestADirectoryReadLateIsSavedLikeTheRest(_LiveRepo):
    """Check the saved branch for a nested directory the scan leaves out by name."""

    def test_its_payload_is_left_off_and_its_other_files_are_saved(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.write(self.repo, "packages/app/dist/text.woff", LOADER)
        self.write(self.repo, "packages/app/dist/notes.txt", "mine\n")
        kept = self.run_fix().kept
        self.assertEqual(["README.md", "packages/app/dist/notes.txt", "src/app.js"],
                         sorted(self.tree(kept.branch)))
        self.assertEqual(0, kept.unread)


class TestTheSavedCountIsTheOperatorsFiles(_LiveRepo):
    """Check the number of files the run says it saved."""

    def test_a_removed_committed_payload_is_not_counted(self):
        self.write(self.repo, "fonts/text.woff", LOADER)
        self.commit(self.repo, "payload")
        self.write(self.repo, "src/app.js", "module.exports = 2;\n")
        self.assertEqual(1, self.run_fix().kept.files)


if __name__ == "__main__":
    unittest.main()
