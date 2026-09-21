#!/usr/bin/env python3
"""The acceptance target for `Ndevu12/saw#286`: a repository carrying a live infection is
remediated, and the report matches what was measured. The shape is described there.

Extends the spec pinned by `test_amend.py` rather than restating it. Each element is asserted
against the verb that owns it: `fix` answers for the working tree, `amend` answers for history.
"""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout, redirect_stderr

from stayawake.bots.security import remediator
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.support.gitrepo import GitSandbox

GENUINE_FONT = b"wOFF\x00\x01\x00\x00genuine third-party font bytes\n"
OTHER_FONT = b"wOFF\x00\x01\x00\x00a second genuine font\n"
LOADER = "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n"
LAUNCHER = ('{"version":"2.0.0","tasks":[{"label":"prep","type":"shell",'
            '"command":"node ./public/fonts/text.woff",'
            '"runOptions":{"runOn":"folderOpen"}}]}\n')
SETTINGS_WITH_BLOCK = ('{"editor.tabSize":2,"editor.formatOnSave":true,'
                       '"task.allowAutomaticTasks":"on","files.eol":"\\n"}\n')
PACKAGE_JSON = '{"name":"example-app","version":"1.0.0","main":"src/index.js"}\n'
INDEX_JS = "export const greet = (n) => `hi ${n}`;\n"

PROJECT_OWN = ("package.json", "src/index.js")
GENUINE_ASSETS = ("public/fonts/inter-regular.woff", "public/fonts/roboto.woff")
THE_LOADER = "public/fonts/text.woff"
THE_LAUNCHER = ".vscode/tasks.json"
THE_SHARED_CONFIG = ".vscode/settings.json"


class _InfectedProject(GitSandbox):
    """A repository carrying all four elements the epic measures against."""

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        (self.d / "public" / "fonts").mkdir(parents=True)
        (self.d / ".vscode").mkdir()
        (self.d / "src").mkdir()
        (self.d / GENUINE_ASSETS[0]).write_bytes(GENUINE_FONT)
        (self.d / GENUINE_ASSETS[1]).write_bytes(OTHER_FONT)
        (self.d / THE_LOADER).write_text(LOADER)
        (self.d / THE_LAUNCHER).write_text(LAUNCHER)
        (self.d / THE_SHARED_CONFIG).write_text(SETTINGS_WITH_BLOCK)
        (self.d / "package.json").write_text(PACKAGE_JSON)
        (self.d / "src" / "index.js").write_text(INDEX_JS)
        self.commit(self.d, "project and payload")
        self.base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.before = {p: self._blob(f"{self.base}:{p}")
                       for p in PROJECT_OWN + GENUINE_ASSETS}

    def _blob(self, spec):
        return self.git(self.d, "rev-parse", spec).strip()

    def _scan(self, root=None):
        return scan_target(LocalRepoTarget(root or self.d, "project", ScanOptions()),
                           load_signatures(), [])

    def _fix(self):
        """Run the verb that answers for the working tree. Returns the branch it prepared."""
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            remediator.fix(None, paths=[str(self.d)], no_stream=True)
        return f"security/auto-clean-{self.base}"

    def _on(self, branch, path):
        r = self.git_may_fail(self.d, "rev-parse", f"{branch}:{path}")
        return r.stdout.strip() if r.returncode == 0 else None

    def _refs(self):
        return [l.strip() for l in
                self.git(self.d, "for-each-ref", "--format=%(refname)").splitlines() if l.strip()]


class TestTheFixtureIsWhatTheEpicDescribes(_InfectedProject):
    """Check the fixture carries the infection the epic is measured against."""

    def test_the_scanner_confirms_all_four_elements(self):
        r = self._scan()
        self.assertEqual("infected", r.verdict)
        confirmed = {f.signature_id for f in r.findings if f.confidence == "confirmed"}
        self.assertIn("fake-font-text-woff", confirmed)
        self.assertIn("vscode-task-runs-font", confirmed)
        self.assertIn("vscode-allow-automatic-tasks", confirmed)

    def test_the_genuine_assets_are_not_themselves_findings(self):
        flagged = {f.path for f in self._scan().findings}
        for asset in GENUINE_ASSETS:
            self.assertNotIn(asset, flagged)


class TestTheWorkingTreeIsRemediated(_InfectedProject):
    """Check what the verb that owns the working tree answers for."""

    def test_the_loader_is_absent_from_the_working_tree(self):
        self.assertIsNone(self._on(self._fix(), THE_LOADER))

    def test_the_launcher_file_is_absent(self):
        self.assertIsNone(self._on(self._fix(), THE_LAUNCHER))

    def test_the_injected_block_is_gone_and_the_real_settings_survive(self):
        branch = self._fix()
        kept = self.git(self.d, "show", f"{branch}:{THE_SHARED_CONFIG}")
        self.assertNotIn("allowAutomaticTasks", kept)
        self.assertIn("editor.tabSize", kept)
        self.assertIn("formatOnSave", kept)

    def test_the_genuine_assets_survive_untouched(self):
        branch = self._fix()
        for asset in GENUINE_ASSETS:
            self.assertEqual(self.before[asset], self._on(branch, asset), asset)

    def test_nothing_is_copied_aside(self):
        self._fix()
        self.assertEqual("", self.git(self.d, "status", "--porcelain").strip())

    def test_the_projects_own_content_is_byte_identical(self):
        branch = self._fix()
        for path in PROJECT_OWN:
            self.assertEqual(self.before[path], self._on(branch, path), path)

    def test_a_scan_of_the_remediated_tree_reports_clean(self):
        branch = self._fix()
        self.git(self.d, "checkout", "-q", branch)
        self.assertEqual("clean", self._scan().verdict)


class TestHistoryIsRemediated(_InfectedProject):
    """Check what the verb that owns history answers for."""

    def _refs_still_holding_the_loader(self):
        loader = self._blob(f"{self.base}:{THE_LOADER}")
        return [r for r in self._refs()
                if loader in self.git(self.d, "ls-tree", "-r", r)]

    @unittest.expectedFailure
    def test_the_loader_is_absent_from_every_ref(self):
        self._fix()
        self.assertEqual([], self._refs_still_holding_the_loader())

    def test_the_loader_does_survive_in_a_ref_today(self):
        """Pin the reason the criterion above fails."""
        self._fix()
        self.assertEqual([f"refs/heads/{self.base}"], self._refs_still_holding_the_loader())


class TestTheReportMatchesTheResult(_InfectedProject):
    """Check that what is reported is measured from the result, never asserted from the plan."""

    def _fix_exit(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return remediator.fix(None, paths=[str(self.d)], no_stream=True)

    @unittest.expectedFailure
    def test_it_does_not_report_success_while_the_loader_survives(self):
        code = self._fix_exit()
        loader = self._blob(f"{self.base}:{THE_LOADER}")
        survives = any(loader in self.git(self.d, "ls-tree", "-r", r) for r in self._refs())
        if survives:
            self.assertNotEqual(0, code)

    def test_it_does_report_success_today(self):
        """Pin the exit code reported today."""
        self.assertEqual(0, self._fix_exit())


if __name__ == "__main__":
    unittest.main()
