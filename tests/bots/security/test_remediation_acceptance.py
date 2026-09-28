#!/usr/bin/env python3
"""The acceptance target for `Ndevu12/saw#286`: a repository carrying a live infection is
remediated end to end by `saw fix` then `saw fix amend`, and what is reported matches what was
measured. The shape is described in `Ndevu12/saw#287`.

`fix` answers for the checkout and the branch it prepares; `amend` answers for history. Whether a
payload survives is decided by looking for its bytes on disk and in every stored object, never by
asking the scanner whether it still finds them.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import unittest
from contextlib import redirect_stdout, redirect_stderr

from stayawake.bots.security import remediator
from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.lib.git.write.push import PushResult
from tests.support.gitrepo import GitSandbox
from tests.support.offline_github import github_answers

GENUINE_FONT = b"wOFF\x00\x01\x00\x00genuine third-party font bytes\n"
OTHER_FONT = b"wOFF\x00\x01\x00\x00a second genuine font\n"
PAYLOAD_MARK = "String.fromCharCode(118,97,114)"
LOADER = f"var _0x={PAYLOAD_MARK};eval(_0x+\" x=1\");\n"
LAUNCHER = ('{"version":"2.0.0","tasks":[{"label":"prep","type":"shell",'
            '"command":"node ./public/fonts/text.woff",'
            '"runOptions":{"runOn":"folderOpen"}}]}\n')
SETTINGS_CLEAN = '{"editor.tabSize":2,"editor.formatOnSave":true,"files.eol":"\\n"}\n'
SETTINGS_INJECTED = ('{"editor.tabSize":2,"editor.formatOnSave":true,'
                     '"task.allowAutomaticTasks":"on","files.eol":"\\n"}\n')
REAL_SETTINGS = {"editor.tabSize": 2, "editor.formatOnSave": True, "files.eol": "\n"}
PACKAGE_JSON = '{"name":"example-app","version":"1.0.0","main":"src/index.js"}\n'
INDEX_JS = "export const greet = (n) => `hi ${n}`;\n"

PROJECT_OWN = ("package.json", "src/index.js")
GENUINE_ASSETS = ("public/fonts/inter-regular.woff", "public/fonts/roboto.woff")
THE_LOADER = "public/fonts/text.woff"
THE_LAUNCHER = ".vscode/tasks.json"
THE_SHARED_CONFIG = ".vscode/settings.json"


def _pushed(branch, dest, lease):
    return PushResult(True)


class _InfectedProject(GitSandbox):
    """A repository with a clean history, then one commit carrying all four elements."""

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        (self.d / "public" / "fonts").mkdir(parents=True)
        (self.d / ".vscode").mkdir()
        (self.d / "src").mkdir()
        (self.d / GENUINE_ASSETS[0]).write_bytes(GENUINE_FONT)
        (self.d / GENUINE_ASSETS[1]).write_bytes(OTHER_FONT)
        (self.d / THE_SHARED_CONFIG).write_text(SETTINGS_CLEAN)
        (self.d / "package.json").write_text(PACKAGE_JSON)
        (self.d / "src" / "index.js").write_text(INDEX_JS)
        self.commit(self.d, "the project, before anything happened")
        self.clean_root = self.rev(self.d)

        (self.d / THE_LOADER).write_text(LOADER)
        (self.d / THE_LAUNCHER).write_text(LAUNCHER)
        (self.d / THE_SHARED_CONFIG).write_text(SETTINGS_INJECTED)
        self.commit(self.d, "add build tooling")
        self.base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.before = {p: (self.d / p).read_bytes() for p in PROJECT_OWN + GENUINE_ASSETS}
        self.files_before = self._files_on_disk()

    def _files_on_disk(self):
        found = set()
        for top, dirs, files in os.walk(self.d):
            dirs[:] = [d for d in dirs if d != ".git"]
            found |= {os.path.relpath(os.path.join(top, f), self.d) for f in files}
        return found

    def _payload_on_disk(self):
        """Every file under the checkout, outside git's store, holding the payload's bytes."""
        return sorted(p for p in self._files_on_disk()
                      if PAYLOAD_MARK.encode() in (self.d / p).read_bytes())

    def _payload_in_history(self):
        """Every stored object a branch or tag still reaches that holds the payload's bytes."""
        out = []
        listing = self.git(self.d, "rev-list", "--objects", "--all")
        for line in listing.splitlines():
            oid = line.split()[0] if line.split() else ""
            if self.git_may_fail(self.d, "cat-file", "-t", oid).stdout.strip() != "blob":
                continue
            stored = subprocess.run(["git", "-C", str(self.d), "cat-file", "blob", oid],
                                    capture_output=True, stdin=subprocess.DEVNULL).stdout
            if PAYLOAD_MARK.encode() in stored:
                out.append(oid)
        return out

    def _committed(self, path):
        """The bytes HEAD stores at `path`."""
        return subprocess.run(["git", "-C", str(self.d), "cat-file", "blob", f"HEAD:{path}"],
                              capture_output=True, stdin=subprocess.DEVNULL).stdout

    def _refs(self):
        return [line.strip() for line in
                self.git(self.d, "for-each-ref", "--format=%(refname)").splitlines() if line]

    def _scan(self, root=None):
        return scan_target(LocalRepoTarget(root or self.d, "project", ScanOptions()),
                           load_signatures(), [])

    def _fix(self):
        """Run the verb that answers for the checkout. Returns its exit code."""
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return remediator.fix(None, paths=[str(self.d)], no_stream=True)

    def _amend(self, pusher=_pushed, remote_head=None):
        """Run the verb that answers for history, offline, on the operator's own checkout as
        `saw fix amend` does. `remote_head(branch)` is what the remote holds ("" for nothing);
        by default it holds every local branch except saved work. Returns its outcome."""
        def held(branch):
            return "" if branch.startswith("saw/uncommitted-") else self.rev(self.d, branch)
        with github_answers(remote_head or held), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                 pusher=pusher, operator_checkout=True)


class TestTheFixtureCarriesTheInfection(_InfectedProject):
    """Check the fixture is what the acceptance target is measured against."""

    def test_it_has_a_clean_history_before_the_infection(self):
        tree = self.git(self.d, "ls-tree", "-r", "--name-only", self.clean_root).split()
        self.assertNotIn(THE_LOADER, tree)
        self.assertNotIn(THE_LAUNCHER, tree)

    def test_the_scanner_confirms_the_infection(self):
        result = self._scan()
        self.assertEqual("infected", result.verdict)
        confirmed = {f.signature_id for f in result.findings if f.confidence == "confirmed"}
        for signature in ("fake-font-text-woff", "vscode-task-runs-font",
                          "vscode-allow-automatic-tasks"):
            self.assertIn(signature, confirmed)

    def test_the_genuine_assets_are_not_themselves_findings(self):
        flagged = {f.path for f in self._scan().findings}
        for asset in GENUINE_ASSETS:
            self.assertNotIn(asset, flagged)

    def test_the_payload_is_where_the_measures_look(self):
        self.assertEqual([THE_LOADER], self._payload_on_disk())
        self.assertTrue(self._payload_in_history())


class _Remediated(_InfectedProject):
    """The fixture after `saw fix` and then `saw fix amend`."""

    def setUp(self):
        super().setUp()
        self.fix_exit = self._fix()
        self.amended = self._amend()


class TestTheLoaderIsGone(_Remediated):
    """Criterion 1: the loader is gone."""

    def test_no_file_in_the_checkout_holds_it(self):
        self.assertEqual([], self._payload_on_disk())

    def test_no_ref_reaches_it(self):
        self.assertEqual([], self._payload_in_history())


class TestEveryLauncherIsDisarmed(_Remediated):
    """Criterion 2: every mechanism that launches it is gone or disarmed."""

    def test_the_launcher_file_is_gone(self):
        self.assertFalse((self.d / THE_LAUNCHER).exists())
        self.assertNotIn(THE_LAUNCHER,
                         self.git(self.d, "ls-tree", "-r", "--name-only", "HEAD").split())

    def test_the_injected_setting_is_gone_and_the_real_ones_survive(self):
        on_disk = json.loads((self.d / THE_SHARED_CONFIG).read_text())
        committed = json.loads(self.git(self.d, "show", f"HEAD:{THE_SHARED_CONFIG}"))
        for settings in (on_disk, committed):
            self.assertNotIn("task.allowAutomaticTasks", settings)
            for key, value in REAL_SETTINGS.items():
                self.assertEqual(value, settings.get(key), key)


class TestTheForeignTreeKeepsItsGenuineFiles(_Remediated):
    """Criterion 3: the genuine third-party files survive, and nothing is copied anywhere."""

    def test_the_genuine_assets_are_untouched_on_disk_and_in_history(self):
        for asset in GENUINE_ASSETS:
            self.assertEqual(self.before[asset], (self.d / asset).read_bytes(), asset)
            self.assertEqual(self.before[asset],
                             self._committed(asset), asset)

    def test_nothing_new_appears_in_the_checkout(self):
        self.assertEqual(set(), self._files_on_disk() - self.files_before)


class TestTheProjectsOwnContentIsUntouched(_Remediated):
    """Criterion 4: the project's own content is byte-identical."""

    def test_on_disk_and_in_history(self):
        for path in PROJECT_OWN:
            self.assertEqual(self.before[path], (self.d / path).read_bytes(), path)
            self.assertEqual(self.before[path],
                             self._committed(path), path)


class TestARescanIsClean(_Remediated):
    """Criterion 5: a re-scan of the result is clean."""

    def test_the_checkout_scans_clean(self):
        self.assertEqual("clean", self._scan().verdict)


class TestTheReportMatchesTheResult(_Remediated):
    """Criterion 6: the report says exactly what was measured."""

    def test_history_is_reported_clean_only_when_no_ref_reaches_the_loader(self):
        self.assertEqual(not self._payload_in_history(), self.amended.completed)

    def test_fix_reports_success_only_when_nothing_is_left_on_disk(self):
        if self._payload_on_disk():
            self.assertNotEqual(0, self.fix_exit)


class _AVariantOfTheInfection(_InfectedProject):
    """The fixture with one more commit on top, written by `later()`."""

    def setUp(self):
        super().setUp()
        self.later()
        self.commit(self.d, "a later change")
        self.before = {p: (self.d / p).read_bytes() for p in PROJECT_OWN + GENUINE_ASSETS}

    def later(self):
        raise NotImplementedError

    def _settings(self):
        return json.loads(subprocess.run(
            ["git", "-C", str(self.d), "cat-file", "blob", f"HEAD:{THE_SHARED_CONFIG}"],
            capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape"))

    def assert_no_payload_is_left(self):
        self.assertEqual([], self._payload_on_disk())
        self.assertEqual([], self._payload_in_history())
        for path in PROJECT_OWN + GENUINE_ASSETS:
            self.assertEqual(self.before[path], self._committed(path), path)


class TestAnEscapedSettingsKeyIsStrippedFromHistory(_AVariantOfTheInfection):
    """Check a settings file only a whole-file rewrite can repair, on a clean checkout."""

    def later(self):
        (self.d / THE_SHARED_CONFIG).write_text(
            '{"editor.tabSize":2,"task\\u002eallowAutomaticTasks":"on","files.eol":"\\n"}\n')

    def test_amend_alone_leaves_no_payload_and_keeps_the_real_settings(self):
        self._amend()
        self.assert_no_payload_is_left()
        settings = self._settings()
        self.assertNotIn("task.allowAutomaticTasks", settings)
        self.assertEqual(2, settings.get("editor.tabSize"))


class TestSettingsThatAreNotUtf8AreStrippedByteExact(_AVariantOfTheInfection):
    """Check a settings file holding a byte that is not UTF-8."""

    def later(self):
        (self.d / THE_SHARED_CONFIG).write_bytes(
            b'{"editor.x":"\xff","editor.tabSize":2,"task.allowAutomaticTasks":"on"}\n')

    def test_amend_alone_strips_the_setting_and_keeps_the_other_bytes(self):
        self._amend()
        self.assert_no_payload_is_left()
        stored = subprocess.run(
            ["git", "-C", str(self.d), "cat-file", "blob", f"HEAD:{THE_SHARED_CONFIG}"],
            capture_output=True, check=True).stdout
        self.assertEqual(b'{"editor.x":"\xff","editor.tabSize":2}\n', stored)


class TestALoaderChangedInALaterCommitIsGone(_AVariantOfTheInfection):
    """Check a loader whose bytes differ between the commits that hold it."""

    def later(self):
        (self.d / THE_LOADER).write_text(LOADER + "// v2\n")

    def test_fix_then_amend_leaves_no_payload(self):
        self._fix()
        self._amend()
        self.assert_no_payload_is_left()
        self.assertEqual("clean", self._scan().verdict)


class TestALauncherChangedInALaterCommitIsGone(_AVariantOfTheInfection):
    """Check a launcher whose bytes differ between the commits that hold it."""

    def later(self):
        (self.d / THE_LAUNCHER).write_text(LAUNCHER.replace('"prep"', '"prepare"'))

    def test_fix_then_amend_leaves_no_launcher(self):
        self._fix()
        self._amend()
        self.assert_no_payload_is_left()
        self.assertFalse((self.d / THE_LAUNCHER).exists())
        for ref in self._refs():
            tree = self.git(self.d, "ls-tree", "-r", "--name-only", ref).split()
            self.assertNotIn(THE_LAUNCHER, tree, ref)


class TestAPayloadAmendCannotTakeOutIsNamedNotBlamedOnTheCheckout(_InfectedProject):
    """Check the reason given when only a payload the rewrite cannot take out stops the move."""

    def test_it_is_reported_as_manual_recovery(self):
        from unittest import mock
        self._fix()
        with mock.patch("stayawake.bots.security.pr.amend._foreign_targets", return_value=[]):
            outcome = self._amend()
        causes = [r.cause.name for r in outcome.reasons]
        self.assertIn("PAYLOAD_NEEDS_MANUAL_RECOVERY", causes)
        self.assertNotIn("WORKING_TREE_NOT_CLEAN", causes)


class TestTheOperatorsOwnWorkIsKept(_InfectedProject):
    """Check that the operator's own uncommitted work survives the rewrite, as `saw fix` keeps it."""

    def test_an_edit_the_rewrite_does_not_touch_stays_and_the_payload_goes(self):
        self._fix()
        (self.d / "package.json").write_text(PACKAGE_JSON.replace("1.0.0", "1.1.0"))
        self._amend()
        self.assertIn("1.1.0", (self.d / "package.json").read_text())
        self.assertEqual([], self._payload_in_history())
        self.assertEqual([], self._payload_on_disk())

    def test_an_edit_to_a_file_the_rewrite_repairs_stays_repaired(self):
        (self.d / THE_SHARED_CONFIG).write_text(SETTINGS_INJECTED.replace(
            '"files.eol"', '"editor.wordWrap":"on","files.eol"'))
        self._amend()
        settings = json.loads((self.d / THE_SHARED_CONFIG).read_text())
        self.assertEqual("on", settings.get("editor.wordWrap"))
        self.assertNotIn("task.allowAutomaticTasks", settings)
        self.assertEqual([], self._payload_in_history())

    def test_a_refused_push_puts_the_branch_back_and_keeps_the_edit(self):
        (self.d / THE_SHARED_CONFIG).write_text(SETTINGS_INJECTED.replace(
            '"files.eol"', '"editor.wordWrap":"on","files.eol"'))
        before = self.rev(self.d)
        outcome = self._amend(pusher=lambda branch, dest, lease: PushResult(False))
        self.assertFalse(outcome.completed)
        self.assertEqual(before, self.rev(self.d))
        self.assertIn("editor.wordWrap", (self.d / THE_SHARED_CONFIG).read_text())

    def test_a_merge_in_progress_stops_it_before_anything_moves(self):
        self.git(self.d, "checkout", "-q", "-b", "side", self.clean_root)
        (self.d / "notes.md").write_text("side\n")
        self.commit(self.d, "side work")
        self.git(self.d, "checkout", "-q", self.base)
        self.git_may_fail(self.d, "merge", "--no-commit", "--no-ff", "side")
        before = self.rev(self.d)
        outcome = self._amend()
        self.assertIn("WORKING_TREE_NOT_CLEAN", [r.cause.name for r in outcome.reasons])
        self.assertEqual(before, self.rev(self.d))
        self.assertEqual(0, self.git_may_fail(self.d, "rev-parse", "-q", "--verify",
                                              "MERGE_HEAD").returncode)

    def test_undoing_the_move_after_fix_never_writes_the_payload_back(self):
        from unittest import mock
        from stayawake.bots.security.remediation import live
        self._fix()
        with mock.patch.object(live, "clean_checkout", return_value=live.CheckoutResult()):
            self._amend(pusher=lambda branch, dest, lease: PushResult(False))
        self.assertEqual([], self._payload_on_disk())
        self.assertFalse((self.d / THE_LAUNCHER).exists())

    def test_undoing_the_move_keeps_what_was_staged(self):
        from unittest import mock
        from stayawake.bots.security.remediation import live
        self._fix()
        self.git(self.d, "add", "-A")
        before = self.git(self.d, "status", "--porcelain")
        with mock.patch.object(live, "clean_checkout", return_value=live.CheckoutResult()):
            self._amend(pusher=lambda branch, dest, lease: PushResult(False))
        self.assertEqual(before, self.git(self.d, "status", "--porcelain"))

    def test_a_folder_replaced_by_a_link_stops_it_and_the_link_stays(self):
        import shutil
        outside = self.root / "outside"
        shutil.copytree(self.d / ".vscode", outside)
        shutil.rmtree(self.d / ".vscode")
        (self.d / ".vscode").symlink_to(outside)
        outcome = self._amend()
        self.assertIn("WORKING_TREE_NOT_CLEAN", [r.cause.name for r in outcome.reasons])
        self.assertTrue((self.d / ".vscode").is_symlink())

    def test_saved_work_the_remote_already_holds_is_cleaned_there_too(self):
        self.git(self.d, "branch", "saw/uncommitted-earlier", self.base)
        pushed = []

        def recorded(branch, dest, lease):
            pushed.append(branch)
            return PushResult(True)
        self._amend(pusher=recorded, remote_head=lambda branch: self.rev(self.d, branch))
        self.assertIn("saw/uncommitted-earlier", pushed)

    def test_when_only_saved_work_carries_it_the_saved_work_is_cleaned(self):
        self.git(self.d, "branch", "saw/uncommitted-earlier", self.base)
        self.git(self.d, "checkout", "-q", "--detach", self.base)
        self.git(self.d, "branch", "-D", self.base)
        outcome = self._amend()
        self.assertIn("SAVED_WORK_CLEANED_HERE", [r.cause.name for r in outcome.reasons])
        tree = self.git(self.d, "ls-tree", "-r", "--name-only", "saw/uncommitted-earlier").split()
        self.assertNotIn(THE_LOADER, tree)

    def test_an_untracked_copy_is_removed_and_not_called_manual_recovery(self):
        (self.d / "public" / "fonts" / "extra.woff").write_text(LOADER)
        outcome = self._amend()
        manual = [r for r in outcome.reasons if r.cause.name == "PAYLOAD_NEEDS_MANUAL_RECOVERY"]
        self.assertFalse(any("extra.woff" in (r.subjects or "") for r in manual))
        self.assertEqual([], self._payload_on_disk())

    def test_work_saved_by_fix_is_cleaned_locally_and_never_pushed(self):
        (self.d / "package.json").write_text(PACKAGE_JSON.replace("1.0.0", "1.2.0"))
        self._fix()
        saved = [r for r in self._refs() if "/saw/uncommitted-" in r]
        self.assertTrue(saved)
        pushed = []

        def recorded(branch, dest, lease):
            pushed.append(branch)
            return PushResult(True)
        self._amend(pusher=recorded)
        self.assertFalse([b for b in pushed if b.startswith("saw/uncommitted-")])
        self.assertEqual([], self._payload_in_history())
        self.assertIn("1.2.0", (self.d / "package.json").read_text())


if __name__ == "__main__":
    unittest.main()
