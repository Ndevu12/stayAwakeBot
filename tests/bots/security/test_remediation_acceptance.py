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
            if PAYLOAD_MARK in self.git_may_fail(self.d, "cat-file", "-p", oid).stdout:
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

    def _amend(self):
        """Run the verb that answers for history, offline. Returns its outcome."""
        with github_answers(lambda branch: self.rev(self.d, branch)), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                 pusher=_pushed)


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

    @unittest.expectedFailure
    def test_no_ref_reaches_it(self):
        self.assertEqual([], self._payload_in_history())


class TestEveryLauncherIsDisarmed(_Remediated):
    """Criterion 2: every mechanism that launches it is gone or disarmed."""

    @unittest.expectedFailure
    def test_the_launcher_file_is_gone(self):
        self.assertFalse((self.d / THE_LAUNCHER).exists())
        self.assertNotIn(THE_LAUNCHER,
                         self.git(self.d, "ls-tree", "-r", "--name-only", "HEAD").split())

    @unittest.expectedFailure
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


if __name__ == "__main__":
    unittest.main()
