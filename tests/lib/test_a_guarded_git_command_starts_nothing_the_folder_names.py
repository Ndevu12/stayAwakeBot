#!/usr/bin/env python3
"""`saw govern guard` says how to run the operator's git command in a folder without starting any
program the folder's own settings name, while the operator's own identity, transports, signing, hooks
and credential helpers keep working. Each case drives real git with the answer applied, in a folder armed
with a program for one kind of setting, and requires that the program left no marker."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake import cli
from stayawake.lib.git import folder_guard
from stayawake.utils import scratch
from tests.support.hostile_repo import HostileRepo, HostileRepoSandbox

RAN = "a program the folder's settings name started"
CREDENTIAL_QUESTION = "protocol=https\nhost=example.invalid\n\n"
PROGRAM = "@PROGRAM@"
SOURCE = "@SOURCE@"

# Each case: the marker its program leaves, the folder's settings naming it, and the operator's
# command that reaches it.
CASES = (
    ("alias.bang", "[alias]\n\tbang = !@PROGRAM@\n", ("bang",)),
    ("alias.option", "[alias]\n\toption = -c core.fsmonitor=@PROGRAM@ status\n", ("option",)),
    ("remote.uploadpack", '[remote "local"]\n\turl = @SOURCE@\n\tuploadpack = @PROGRAM@\n',
     ("fetch", "-q", "local")),
    ("remote.receivepack", '[remote "local"]\n\turl = @SOURCE@\n\treceivepack = @PROGRAM@\n',
     ("push", "-q", "local", "HEAD:refs/heads/pushed")),
    ("core.alternateRefsCommand", "[core]\n\talternateRefsCommand = @PROGRAM@\n",
     ("fetch", "-q", SOURCE)),
    ("core.gitProxy", "[core]\n\tgitProxy = @PROGRAM@\n", ("ls-remote", "git://127.0.0.1:1/x")),
    ("hook.planted", '[hook "planted"]\n\tcommand = @PROGRAM@\n\tevent = pre-commit\n',
     ("commit", "-qm", "work", "--allow-empty")),
    ("credential.url.helper", '[credential "https://example.invalid"]\n\thelper = !@PROGRAM@\n',
     ("credential", "fill")),
    ("diff.external", "[diff]\n\texternal = @PROGRAM@\n", ("diff",)),
    ("core.sshCommand", "[core]\n\tsshCommand = @PROGRAM@\n", ("ls-remote", "ssh://127.0.0.1:1/x")),
)

# The operator's commands driven over the hostile repository, each reaching some of its programs.
OPERATOR_COMMANDS = (
    ("status",), ("diff",), ("log", "-p", "-3"), ("show", "HEAD"), ("grep", "--textconv", "base"),
    ("add", "-A"), ("commit", "-qm", "work", "--allow-empty"), ("stash",), ("stash", "pop"),
    ("checkout", "-q", "-f", "conflict"), ("checkout", "-q", "-f", "main"),
    ("merge", "--no-edit", "conflict"), ("merge", "--abort"), ("fetch", "-q", "origin"),
    ("push", "-q", "origin", "main"), ("ls-remote", "ssh://127.0.0.1:1/x"), ("credential", "fill"),
)


class GuardSandbox(HostileRepoSandbox):
    """A sandbox whose operator has an identity of their own, allowing the transports the cases use."""

    PROTOCOLS = "file:ext:ssh:git:https"

    def setUp(self):
        super().setUp()
        self.operator_config = self.owned(self.root / "operator.gitconfig")
        self.operator_config.write_text(
            "[user]\n\tname = Operator Person\n\temail = operator@example.invalid\n", encoding="utf-8")
        operator = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(self.operator_config)})
        operator.start()
        self.addCleanup(operator.stop)

    def answer(self, folder: Path, *args: str, environ: dict | None = None) -> folder_guard.Guard:
        return folder_guard.guard(folder, list(args), dict(os.environ) if environ is None else environ)

    def guarded(self, folder: Path, *args: str) -> subprocess.CompletedProcess:
        """Run the operator's command in the folder with the guard's answer applied."""
        answer = self.answer(folder, *args)
        self.assertEqual("", answer.refusal, args)
        return self._git(folder, [*answer.arguments, *args], dict(answer.environment))

    def unguarded(self, folder: Path, *args: str) -> subprocess.CompletedProcess:
        return self._git(folder, list(args), {})

    def _git(self, folder: Path, argv: list[str], extra: dict) -> subprocess.CompletedProcess:
        environment = {key: value for key, value in os.environ.items()
                       if key.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
        asks = "credential" in argv
        return subprocess.run(["git", *argv], cwd=folder, env={**environment, **extra},
                              input=CREDENTIAL_QUESTION if asks else None,
                              stdin=None if asks else subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)

    def marks(self, name: str) -> HostileRepo:
        """A sentinel directory and the one program that leaves a marker in it."""
        sentinel = self.owned(self.root / f"{name}-sentinel")
        programs = self.owned(self.root / f"{name}-bin")
        sentinel.mkdir()
        programs.mkdir()
        marks = HostileRepo(repo=self.root, origin=self.root, sentinel=sentinel, bin=programs)
        self._write_mark(marks)
        return marks

    def plain_folder(self, name: str) -> Path:
        folder = self.new_repo(name)
        self.write(folder, "f.txt", "one\n")
        self.commit(folder, "one")
        return folder


class TestTheAnswerKeepsEveryKindOfSettingFromStartingAProgram(GuardSandbox):
    """One folder per kind of setting: unguarded the command starts its program, guarded it does
    not."""

    def test_each_kind_of_setting_starts_nothing_when_guarded(self):
        for marker, settings, command in CASES:
            with self.subTest(setting=marker):
                folder = self.plain_folder(f"folder-{marker}")
                source = self.plain_folder(f"source-{marker}")
                alternate = self.plain_folder(f"alternate-{marker}")
                (folder / ".git" / "objects" / "info" / "alternates").write_text(
                    str(alternate / ".git" / "objects") + "\n", encoding="utf-8")
                marks = self.marks(marker)
                program = self._program(marks, marker)
                with (folder / ".git" / "config").open("a", encoding="utf-8") as config:
                    config.write(settings.replace(PROGRAM, program).replace(SOURCE, str(source)))
                (folder / "f.txt").write_text("changed\n", encoding="utf-8")
                argv = tuple(word.replace(SOURCE, str(source)) for word in command)

                self.unguarded(folder, *argv)
                if marker == "hook.planted" and not marks.fired():
                    self.skipTest("this git runs no hook defined in settings")
                self.assertEqual([marker], marks.fired(), "the case does not reach its program")
                marks.clear()

                self.guarded(folder, *argv)
                self.assertEqual([], marks.fired(), RAN)


class TestTheHostileRepository(GuardSandbox):
    """The operator's everyday commands over a repository naming a program everywhere git runs one."""

    def test_unguarded_the_commands_reach_the_repositorys_programs(self):
        hostile = self.hostile_repo()
        for command in OPERATOR_COMMANDS:
            self.unguarded(hostile.repo, *command)
        fired = set(hostile.fired())
        for expected in ("core.fsmonitor", "filter.clean", "filter.smudge", "filter.process",
                         "filter-named-a=b.clean", "diff.textconv", "merge.driver", "url.insteadOf",
                         "credential.helper", "core.sshCommand", "hook-post-checkout"):
            self.assertIn(expected, fired)

    def test_guarded_the_commands_start_none_of_them(self):
        hostile = self.hostile_repo(redirect_worktree=False)
        for command in OPERATOR_COMMANDS:
            with self.subTest(command=command):
                self.guarded(hostile.repo, *command)
                self.assertEqual([], hostile.fired(), RAN)

    def test_a_setting_whose_name_holds_an_equals_sign_is_given_through_the_environment(self):
        hostile = self.hostile_repo()
        answer = self.answer(hostile.repo, "checkout", "-q", "conflict")
        given = [arg for arg in answer.arguments if arg.startswith("--config-env=filter.a=b.smudge=")]
        self.assertEqual(1, len(given))
        variable = given[0].rsplit("=", 1)[1]
        self.assertTrue(variable.startswith(folder_guard.VALUE_VARIABLE_PREFIX))
        self.assertEqual("", dict(answer.environment)[variable])

    def test_the_environment_stops_allowing_the_transport_the_settings_turn_off(self):
        hostile = self.hostile_repo()
        answer = self.answer(hostile.repo, "fetch", "origin")
        self.assertEqual("file:ssh:git:https", dict(answer.environment)["GIT_ALLOW_PROTOCOL"])

    def test_a_worktree_moved_elsewhere_keeps_its_filters_from_running(self):
        hostile = self.hostile_repo(redirect_worktree=True)
        self.guarded(hostile.repo, "status")
        self.guarded(hostile.repo, "add", "-A")
        self.assertEqual([], hostile.fired(), RAN)


class TestTheOperatorsOwnSettingsStillWork(GuardSandbox):
    """What the operator set themselves still runs in a folder that names programs of its own."""

    def setUp(self):
        super().setUp()
        if shutil.which("ssh-keygen") is None:
            self.skipTest("signing needs ssh-keygen")
        self.key = self.ssh_signing_key()
        self.operator = self.marks("operator")
        hooks = self.owned(self.root / "operator-hooks")
        hooks.mkdir()
        (hooks / "pre-commit").symlink_to(self._program(self.operator, "pre-commit"))
        self.operator_hooks = hooks
        self.operator_config.write_text(
            "[user]\n\tname = Operator Person\n\temail = operator@example.invalid\n"
            f"\tsigningKey = {self.key}\n"
            "[gpg]\n\tformat = ssh\n"
            "[commit]\n\tgpgSign = true\n"
            f"[core]\n\thooksPath = {hooks}\n"
            f'[hook "operatorcheck"]\n\tcommand = {self._program(self.operator, "operatorcheck")}\n'
            "\tevent = pre-commit\n"
            f"[credential]\n\thelper = !{self._program(self.operator, 'operator-helper')}\n",
            encoding="utf-8")

    def hostile_folder(self, extra: str = "") -> tuple[Path, HostileRepo]:
        folder = self.plain_folder("folder")
        for key in ("user.name", "user.email", "commit.gpgsign", "tag.gpgsign"):
            self.git(folder, "config", "--unset", key)
        planted = self.marks("planted")
        hooks = folder / ".git" / "hooks"
        for sample in hooks.iterdir():
            sample.unlink()
        (hooks / "pre-commit").symlink_to(self._program(planted, "hook-pre-commit"))
        settings = (
            f"[core]\n\tfsmonitor = {self._program(planted, 'core.fsmonitor')}\n"
            f"\tsshCommand = {self._program(planted, 'core.sshCommand')}\n"
            f"[credential]\n\thelper = !{self._program(planted, 'credential.helper')}\n" + extra)
        with (folder / ".git" / "config").open("a", encoding="utf-8") as config:
            config.write(settings.replace(PROGRAM, self._program(planted, "named")))
        self.operator.clear()
        return folder, planted

    def test_a_commit_carries_the_operators_identity_and_signature_and_runs_their_hooks(self):
        folder, planted = self.hostile_folder()
        committed = self.guarded(folder, "commit", "-qm", "work", "--allow-empty")
        self.assertEqual(0, committed.returncode, committed.stderr)
        self.assertEqual("Operator Person <operator@example.invalid>",
                         self.git(folder, "log", "-1", "--format=%an <%ae>").strip())
        self.assertIn(b"\ngpgsig ", self.raw_commit(folder, "HEAD"))
        self.assertEqual(["operatorcheck", "pre-commit"], self.operator.fired())
        self.assertEqual([], planted.fired(), RAN)

    def test_the_operators_own_signing_program_comes_back_where_the_folder_names_one(self):
        with self.operator_config.open("a", encoding="utf-8") as config:
            config.write('[gpg "ssh"]\n\tprogram = ssh-keygen\n')
        folder, planted = self.hostile_folder('[gpg "ssh"]\n\tprogram = @PROGRAM@\n')
        committed = self.guarded(folder, "commit", "-qm", "work", "--allow-empty")
        self.assertEqual(0, committed.returncode, committed.stderr)
        self.assertIn(b"\ngpgsig ", self.raw_commit(folder, "HEAD"))
        self.assertEqual([], planted.fired(), RAN)

    def test_the_operators_credential_helper_is_asked_and_the_folders_is_not(self):
        folder, planted = self.hostile_folder()
        self.guarded(folder, "credential", "fill")
        self.assertEqual(["operator-helper"], self.operator.fired())
        self.assertEqual([], planted.fired(), RAN)

    def test_the_operators_own_shell_alias_runs_and_the_folders_of_that_name_does_not(self):
        with self.operator_config.open("a", encoding="utf-8") as config:
            config.write(f"[alias]\n\tmine = !{self._program(self.operator, 'operator-alias')}\n")
        folder, planted = self.hostile_folder("[alias]\n\tmine = !@PROGRAM@\n")
        self.guarded(folder, "mine")
        self.assertEqual(["operator-alias"], self.operator.fired())
        self.assertEqual([], planted.fired(), RAN)

    def test_https_is_still_allowed(self):
        folder, planted = self.hostile_folder()
        listed = self.guarded(folder, "ls-remote", "https://127.0.0.1:1/x")
        self.assertNotEqual(0, listed.returncode)
        self.assertNotIn("not allowed", listed.stderr)
        self.assertEqual([], planted.fired(), RAN)


class TestTheAnswer(GuardSandbox):
    """What the answer holds, and when saw does not vouch for a command."""

    def test_a_folder_that_names_no_program_gets_only_the_hooks_folder_and_the_closed_transport(self):
        folder = self.plain_folder("plain")
        answer = self.answer(folder, "status")
        hooks = Path(os.environ["XDG_STATE_HOME"]) / "saw" / "git-runs-no-hooks"
        self.assertEqual((("core.hookspath", str(hooks)), ("protocol.ext.allow", "never")),
                         answer.settings)
        self.assertEqual(["-c", f"core.hookspath={hooks}", "-c", "protocol.ext.allow=never"],
                         list(answer.arguments))
        self.assertEqual((("GIT_ALLOW_PROTOCOL", "file:ssh:git:https"),), answer.environment)

    def test_the_empty_hooks_folder_outlives_the_run(self):
        folder = self.plain_folder("plain")
        hooks = Path(dict(self.answer(folder, "status").settings)["core.hookspath"])
        scratch.release()
        self.assertTrue(hooks.is_dir())
        self.assertEqual([], list(hooks.iterdir()))

    def test_the_operators_own_hooks_folder_is_kept_when_it_lies_outside_every_folder(self):
        folder = self.plain_folder("plain")
        self.git(folder, "config", "--global", "core.hooksPath", str(self.root / "my-hooks"))
        self.assertEqual(str(self.root / "my-hooks"),
                         dict(self.answer(folder, "status").settings)["core.hookspath"])
        self.git(folder, "config", "--global", "core.hooksPath", ".githooks")
        self.assertNotEqual(".githooks", dict(self.answer(folder, "status").settings)["core.hookspath"])

    def test_a_command_that_reports_a_setting_reports_the_folders_own(self):
        folder = self.plain_folder("plain")
        self.git(folder, "config", "core.sshCommand", "ssh -i folder-key")
        self.assertEqual((), self.answer(folder, "config", "--get", "core.sshCommand").settings)
        self.assertEqual("ssh -i folder-key\n",
                         self.guarded(folder, "config", "--get", "core.sshCommand").stdout)
        self.assertNotEqual((), self.answer(folder, "config", "--edit").settings)
        unguarded = self.unguarded(folder, "rev-parse", "--git-path", "hooks").stdout
        self.assertEqual(unguarded, self.guarded(folder, "rev-parse", "--git-path", "hooks").stdout)

    def test_a_command_that_names_its_own_repository_is_not_vouched_for(self):
        folder = self.plain_folder("plain")
        self.assertTrue(self.answer(folder, "--git-dir", str(folder / ".git"), "status").refusal)
        self.assertTrue(self.answer(folder, "status", environ={**os.environ,
                                                               "GIT_DIR": str(folder / ".git")}).refusal)
        self.assertEqual("", self.answer(folder, "rev-parse", "--git-dir").refusal)

    def test_settings_that_do_not_load_keep_the_command_from_running(self):
        folder = self.plain_folder("plain")
        self.git(folder, "config", "include.path", str(self.root))
        self.assertTrue(self.answer(folder, "status").refusal)

    def test_a_hooks_folder_holding_files_is_not_used(self):
        folder = self.plain_folder("plain")
        hooks, _ = folder_guard.no_hooks_folder()
        (hooks / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        self.assertIn("holds files", self.answer(folder, "status").refusal)

    def test_a_proxy_command_named_by_both_the_operator_and_the_folder_is_not_vouched_for(self):
        folder = self.plain_folder("plain")
        self.git(folder, "config", "core.gitProxy", "folder-proxy")
        self.assertEqual("", dict(self.answer(folder, "fetch").environment)["GIT_PROXY_COMMAND"])
        self.git(folder, "config", "--global", "core.gitProxy", "my-proxy")
        self.assertTrue(self.answer(folder, "fetch").refusal)

    def test_a_folder_outside_any_repository_gets_the_hooks_folder_and_the_closed_transport(self):
        outside = self.owned(self.root / "outside")
        outside.mkdir()
        answer = self.answer(outside, "init")
        self.assertEqual("", answer.refusal)
        self.assertEqual(["core.hookspath", "protocol.ext.allow"], [key for key, _ in answer.settings])

    def test_saw_prints_it_as_the_govern_document(self):
        folder = self.plain_folder("plain")
        printed = io.StringIO()
        with redirect_stdout(printed):
            cli.main(["govern", "guard", "--json", "--repo", str(folder), "--", "status"])
        document = json.loads(printed.getvalue())
        self.assertEqual("schema_version", next(iter(document)))
        self.assertTrue(document["guarded"])
        self.assertEqual(["core.hookspath", "protocol.ext.allow"],
                         [setting["key"] for setting in document["settings"]])


if __name__ == "__main__":
    unittest.main()
