#!/usr/bin/env python3
"""What a run does to the checkout the operator is standing in."""
from __future__ import annotations

import unittest
from pathlib import Path

from stayawake.bots.security.remediation import live, preserve
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.scratchroot import OwnTempRoot

LOADER = "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n"
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
        return result

    def test_a_person_at_a_terminal_is_told_which_path(self):
        self.assertIn("public/fonts/text.woff", self._unfinished().note(detail=True))

    def test_an_automated_run_is_given_the_count_only(self):
        note = self._unfinished().note()
        self.assertNotIn("public/fonts", note)
        self.assertIn("1 still to deal with", note)


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
        self.assertIn("not clean", result.note())

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


class TestAConfirmedFindingNoRemovalCanExpress(OwnTempRoot):
    """Check a checkout whose confirmed finding is repaired rather than unlinked."""

    def setUp(self):
        super().setUp()
        self.root = (self.tmp / "project").resolve()
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

    def test_what_was_found_is_turned_off_in_the_file(self):
        result = self._checkout()
        self.assertTrue(result.infected, "the fixture must carry a confirmed finding")
        self.assertIn('"task.allowAutomaticTasks": "off"',
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
        self.assertIn("took what was found out of", self._checkout().note())

    def test_the_operators_own_file_is_untouched(self):
        self._checkout()
        self.assertEqual("my own work\n", (self.root / "notes.md").read_text())


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

    def test_a_run_with_none_of_those_is_complete(self):
        self.assertTrue(live.CheckoutResult().complete)


if __name__ == "__main__":
    unittest.main()
