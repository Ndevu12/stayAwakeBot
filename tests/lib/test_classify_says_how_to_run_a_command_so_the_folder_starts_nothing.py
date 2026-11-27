#!/usr/bin/env python3
"""`saw govern classify` says, in `run_with`, how to run a git command it runs directly without
starting any program the folder's own settings name, while the operator's own identity, transports,
signing, hooks and credential helpers keep working. Each case drives real git with `run_with`
applied, in a folder armed with a program for one kind of setting, and requires that the program left
no marker."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import unittest
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from stayawake import cli
from stayawake.bots.security import govern
from stayawake.lib.git import folder_guard, runs_directly
from stayawake.utils import scratch
from tests.support.hostile_repo import HostileRepo, HostileRepoSandbox

RAN = "a program the folder's settings name started"
CREDENTIAL_QUESTION = "protocol=https\nhost=example.invalid\n\n"
PROGRAM = "@PROGRAM@"
SOURCE = "@SOURCE@"
OUTPUT = "@OUTPUT@"
OPERATOR_PROGRAMS = ("vim", "vimdiff", "firefox", "man")
"""Programs on the operator's own path that a tool falls back to, each doing nothing."""
SANDBOX_SETTINGS_VARIABLES = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")
"""The variables the sandbox names its own settings files with, which an operator's terminal does
not set and which make saw check every command."""
MAY_BE_MISSING = frozenset({"hook.planted", "alias.command", "imap.tunnel"})
"""Cases this git may not support. One whose program does not start unguarded is skipped."""

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
    ("tar.command", '[tar "planted"]\n\tcommand = @PROGRAM@\n',
     ("archive", "--format=planted", "-o", OUTPUT, "HEAD")),
    ("tar.gz.command", '[tar "tar.gz"]\n\tcommand = @PROGRAM@\n', ("archive", "-o", OUTPUT + ".tar.gz", "HEAD")),
    ("difftool.path", '[diff]\n\ttool = vimdiff\n[difftool "vimdiff"]\n\tpath = @PROGRAM@\n', ("difftool", "-y")),
    ("man.path", '[man "man"]\n\tpath = @PROGRAM@\n', ("help", "log")),
    ("man.cmd", '[man]\n\tviewer = planted\n[man "planted"]\n\tcmd = @PROGRAM@\n', ("help", "log")),
    ("browser.path", '[web]\n\tbrowser = firefox\n[browser "firefox"]\n\tpath = @PROGRAM@\n',
     ("web--browse", "http://example.invalid/")),
    ("imap.tunnel", "[imap]\n\ttunnel = @PROGRAM@\n\tfolder = drafts\n", ("imap-send",)),
    ("alias.command", '[alias "sub"]\n\tcommand = !@PROGRAM@\n', ("sub",)),
)

# The operator's commands driven over the hostile repository, each reaching some of its programs.
OPERATOR_COMMANDS = (
    ("status",), ("diff",), ("log", "-p", "-3"), ("show", "HEAD"), ("grep", "--textconv", "base"),
    ("add", "-A"), ("commit", "-qm", "work", "--allow-empty"), ("stash",), ("stash", "pop"),
    ("checkout", "-q", "-f", "conflict"), ("checkout", "-q", "-f", "main"),
    ("merge", "--no-edit", "conflict"), ("merge", "--abort"), ("fetch", "-q", "origin"),
    ("push", "-q", "origin", "main"), ("ls-remote", "ssh://127.0.0.1:1/x"), ("credential", "fill"),
)


@dataclass(frozen=True)
class Answer:
    """What classify answers for a git command: whether saw checks it, the reason when the folder's
    settings are why, and the settings, arguments and environment of its `run_with`."""

    checked: bool
    refusal: str = ""
    settings: tuple = ()
    arguments: tuple = ()
    environment: tuple = ()


def read_answer(body: dict) -> Answer:
    run_with = body.get("run_with")
    if run_with is None:
        return Answer(body["checked"], body.get("reason", "") if body["readable"] else "")
    return Answer(body["checked"], "", tuple((s["key"], s["value"]) for s in run_with["settings"]),
                  tuple(run_with["arguments"]), tuple(run_with["environment"].items()))


class GuardSandbox(HostileRepoSandbox):
    """A sandbox whose operator has an identity of their own, allowing the transports the cases use."""

    PROTOCOLS = "file:ext:ssh:git:https"

    def setUp(self):
        super().setUp()
        self.operator_config = self.owned(self.root / "operator.gitconfig")
        self.operator_config.write_text(
            "[user]\n\tname = Operator Person\n\temail = operator@example.invalid\n", encoding="utf-8")
        tools = self.owned(self.root / "operator-path")
        tools.mkdir()
        for name in OPERATOR_PROGRAMS:
            (tools / name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (tools / name).chmod(0o755)
        operator = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(self.operator_config),
                                                "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"})
        operator.start()
        self.addCleanup(operator.stop)
        decide = runs_directly.decide

        def decide_as_the_operators_terminal(tool, args, folder, environ=None):
            environ = os.environ if environ is None else environ
            return decide(tool, args, folder, {key: value for key, value in environ.items()
                                                if key not in SANDBOX_SETTINGS_VARIABLES})
        decided = mock.patch.object(runs_directly, "decide", decide_as_the_operators_terminal)
        decided.start()
        self.addCleanup(decided.stop)

    def answer(self, folder: Path, *args: str, environ: dict | None = None) -> Answer:
        body, _ = govern.classify(str(folder), "git", list(args),
                                  dict(os.environ) if environ is None else environ)
        return read_answer(body)

    def guarded(self, folder: Path, *args: str, named: dict | None = None) -> subprocess.CompletedProcess:
        """Run the operator's command in the folder with `run_with` applied: the command's own, or
        for a command saw checks, the one classify gives a status in the same folder. Takes the
        folder, the arguments and the variables naming the command's repository."""
        environ = {**os.environ, **(named or {})}
        answer = self.answer(folder, *args, environ=environ)
        if answer.checked and not answer.refusal:
            answer = self.answer(folder, "status", environ=environ)
        self.assertEqual("", answer.refusal, args)
        self.assertFalse(answer.checked, args)
        return self._git(folder, [*answer.arguments, *args], {**(named or {}), **dict(answer.environment)})

    def unguarded(self, folder: Path, *args: str, named: dict | None = None) -> subprocess.CompletedProcess:
        return self._git(folder, list(args), dict(named or {}))

    def _git(self, folder: Path, argv: list[str], extra: dict) -> subprocess.CompletedProcess:
        environment = {key: value for key, value in os.environ.items()
                       if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "browser")}
        fed = (CREDENTIAL_QUESTION if "credential" in argv
               else self._patch(folder) if "imap-send" in argv else None)
        return subprocess.run(["git", *argv], cwd=folder, env={**environment, **extra}, input=fed,
                              stdin=None if fed is not None else subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)

    def _patch(self, folder: Path) -> str:
        return self.git(folder, "format-patch", "--stdout", "-1", "HEAD")

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
                output = str(self.root / f"{marker}.out")
                argv = tuple(word.replace(SOURCE, str(source)).replace(OUTPUT, output) for word in command)

                self.unguarded(folder, *argv)
                if marker in MAY_BE_MISSING and not marks.fired():
                    self.skipTest(f"this git does not run {marker}")
                self.assertEqual([marker], marks.fired(), "the case does not reach its program")
                marks.clear()

                self.guarded(folder, *argv)
                self.assertEqual([], marks.fired(), RAN)


class TestACommandSawChecksCarriesNoRunWith(GuardSandbox):
    def test_a_command_that_may_bring_files_or_runs_an_alias_has_no_run_with(self):
        folder = self.plain_folder("plain")
        self.git(folder, "config", "alias.mine", "!true")
        for command in (("fetch", "origin"), ("checkout", "main"), ("merge", "main"), ("stash", "pop"),
                        ("archive", "HEAD"), ("difftool",), ("mine",)):
            with self.subTest(command=command):
                body, _ = govern.classify(str(folder), "git", list(command), dict(os.environ))
                self.assertTrue(body["checked"])
                self.assertNotIn("run_with", body)


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
        answer = self.answer(hostile.repo, "status")
        given = [arg for arg in answer.arguments if arg.startswith("--config-env=filter.a=b.smudge=")]
        self.assertEqual(1, len(given))
        variable = given[0].rsplit("=", 1)[1]
        self.assertTrue(variable.startswith(folder_guard.VALUE_VARIABLE_PREFIX))
        self.assertEqual("", dict(answer.environment)[variable])

    def test_the_environment_stops_allowing_the_transport_the_settings_turn_off(self):
        hostile = self.hostile_repo()
        answer = self.answer(hostile.repo, "status")
        self.assertEqual("ssh:git:https", dict(answer.environment)["GIT_ALLOW_PROTOCOL"])

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


class TestTheRepositoryTheCommandActsOn(GuardSandbox):
    """The settings read are those of the repository git gives the command, wherever it names it."""

    def assert_starts_only_unguarded(self, marks: HostileRepo, folder: Path, *args: str,
                                     named: dict | None = None) -> None:
        self.unguarded(folder, *args, named=named)
        self.assertNotEqual([], marks.fired(), "the case does not reach its program")
        marks.clear()
        self.guarded(folder, *args, named=named)
        self.assertEqual([], marks.fired(), RAN)

    def test_a_bare_command_reads_the_folder_it_acts_on(self):
        folder = self.plain_folder("folder")
        source = self.plain_folder("source")
        subprocess.run(["git", "init", "-q", "--bare", str(folder)], check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
        marks = self.marks("bare")
        with (folder / "config").open("a", encoding="utf-8") as config:
            config.write(f"[core]\n\tsshCommand = {self._program(marks, 'core.sshCommand')}\n")
        self.assert_starts_only_unguarded(marks, folder, "--bare", "ls-remote", "ssh://127.0.0.1:1/x")

    def test_a_command_naming_another_repository_reads_that_repositorys_settings(self):
        folder = self.plain_folder("folder")
        other = self.plain_folder("other")
        marks = self.marks("other")
        self.git(other, "config", "core.fsmonitor", self._program(marks, "core.fsmonitor"))
        self.write(other, "f.txt", "changed\n")
        self.assert_starts_only_unguarded(marks, folder, "--git-dir", str(other / ".git"), "status")

    def test_the_environment_naming_another_repository_reads_that_repositorys_settings(self):
        folder = self.plain_folder("folder")
        other = self.plain_folder("other")
        marks = self.marks("other")
        self.git(other, "config", "core.fsmonitor", self._program(marks, "core.fsmonitor"))
        self.write(other, "f.txt", "changed\n")
        self.assert_starts_only_unguarded(marks, folder, "status", named={"GIT_DIR": str(other / ".git")})

    def test_a_repository_the_inherited_environment_names_is_the_one_read(self):
        folder = self.plain_folder("folder")
        other = self.plain_folder("other")
        marks = self.marks("inherited")
        self.git(other, "config", "core.fsmonitor", self._program(marks, "core.fsmonitor"))
        self.write(other, "f.txt", "changed\n")
        inherited = mock.patch.dict(os.environ, {"GIT_DIR": str(other / ".git")})
        inherited.start()
        self.addCleanup(inherited.stop)
        self.assert_starts_only_unguarded(marks, folder, "status")

    def test_a_setting_read_from_a_blob_fetches_with_none_of_the_folders_programs(self):
        folder = self.plain_folder("partial")
        origin = self.plain_folder("promisor")
        marks = self.marks("blob")
        for key, value in (("core.repositoryformatversion", "1"), ("extensions.partialClone", "origin"),
                           ("remote.origin.url", str(origin)), ("remote.origin.promisor", "true"),
                           ("remote.origin.uploadpack", self._program(marks, "remote.origin.uploadpack"))):
            self.git(folder, "config", key, value)
        missing = "0123456789abcdef0123456789abcdef01234567"
        for written in ("--blob=" + missing, "--blo=" + missing):
            with self.subTest(written=written):
                marks.clear()
                self.assert_starts_only_unguarded(marks, folder, "config", written, "--list")

    def test_a_repository_on_this_machine_runs_none_of_its_own_programs(self):
        folder = self.plain_folder("folder")
        nested = folder / ".nested.git"
        subprocess.run(["git", "init", "-q", "--bare", str(nested)], check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
        marks = self.marks("nested")
        (nested / "hooks" / "pre-receive").symlink_to(self._program(marks, "pre-receive"))
        self.git(folder, "remote", "add", "origin", str(nested))
        self.assert_starts_only_unguarded(marks, folder, "push", "-q", "origin", "HEAD:refs/heads/pushed")
        listed = self.guarded(folder, "ls-remote", str(nested))
        self.assertIn("not allowed", listed.stderr)
        self.assertEqual([], marks.fired(), RAN)

    def test_a_remote_helper_the_folder_names_is_not_started(self):
        folder = self.plain_folder("folder")
        marks = self.marks("helper")
        (marks.bin / "git-remote-planted").symlink_to("mark")
        self.git(folder, "remote", "add", "origin", "https://example.invalid/x")
        self.git(folder, "config", "remote.origin.vcs", "planted")
        with mock.patch.dict(os.environ, {"PATH": f"{marks.bin}{os.pathsep}{os.environ['PATH']}",
                                          "GIT_ALLOW_PROTOCOL": f"{self.PROTOCOLS}:planted"}):
            self.assert_starts_only_unguarded(marks, folder, "ls-remote", "origin")


class TestTheAnswer(GuardSandbox):
    """What the answer holds, and when saw does not vouch for a command."""

    def test_a_folder_that_names_no_program_gets_only_the_hooks_folder_and_the_closed_transport(self):
        folder = self.plain_folder("plain")
        answer = self.answer(folder, "status")
        hooks = Path(os.environ["XDG_STATE_HOME"]) / "saw" / "git-runs-no-hooks"
        self.assertEqual((("core.hookspath", str(hooks)), ("protocol.ext.allow", "never"),
                          ("protocol.file.allow", "never")), answer.settings)
        self.assertEqual(["-c", f"core.hookspath={hooks}", "-c", "protocol.ext.allow=never",
                          "-c", "protocol.file.allow=never"], list(answer.arguments))
        self.assertEqual((("GIT_ALLOW_PROTOCOL", "ssh:git:https"),), answer.environment)

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
        self.assertTrue(self.answer(folder, "config", "--edit").checked)
        unguarded = self.unguarded(folder, "rev-parse", "--git-path", "hooks").stdout
        self.assertEqual(unguarded, self.guarded(folder, "rev-parse", "--git-path", "hooks").stdout)

    def test_a_repository_the_command_names_that_cannot_be_read_is_not_vouched_for(self):
        folder = self.plain_folder("plain")
        self.assertTrue(self.answer(folder, "--git-dir", str(self.root / "no-such"), "status").refusal)
        self.assertEqual("", self.answer(folder, "rev-parse", "--git-dir").refusal)

    def test_a_program_nothing_keeps_from_running_is_not_vouched_for(self):
        folder = self.plain_folder("plain")
        self.git(folder, "config", "gc.recentObjectsHook", str(self.root / "keeps-objects"))
        self.assertIn("gc.recentobjectshook", self.answer(folder, "gc").refusal)

    def test_a_value_is_set_again_however_the_folder_spells_it(self):
        for key, value, kept_from_running in (("core.fsmonitor", "true ", "false"), ("core.fsmonitor", " yes", "false"),
                                              ("pager.log", "true ", "false"), ("alias.st", "status", "")):
            with self.subTest(key=key, value=value):
                folder = self.plain_folder(f"spelled-{key}-{value.strip()}-{len(value)}")
                self.git(folder, "config", key, value)
                self.assertIn((key, kept_from_running), self.answer(folder, "status").settings)

    def test_a_monitor_spelled_like_a_switch_does_not_start(self):
        folder = self.plain_folder("folder")
        marks = self.marks("switch")
        (marks.bin / "yes").symlink_to("mark")
        self.git(folder, "config", "core.fsmonitor", " yes")
        self.write(folder, "f.txt", "changed\n")
        with mock.patch.dict(os.environ, {"PATH": f"{marks.bin}{os.pathsep}{os.environ['PATH']}"}):
            self.unguarded(folder, "status")
            self.assertEqual(["yes"], marks.fired(), "the case does not reach its program")
            marks.clear()
            self.guarded(folder, "status")
        self.assertEqual([], marks.fired(), RAN)

    def test_a_merge_tool_path_the_folder_names_is_set_again(self):
        folder = self.plain_folder("plain")
        self.git(folder, "config", "mergetool.vimdiff.path", str(self.root / "planted"))
        self.assertIn(("mergetool.vimdiff.path", ""), self.answer(folder, "status").settings)

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
        listing = ("ls-remote", "git://127.0.0.1:1/x")
        self.assertEqual("", dict(self.answer(folder, *listing).environment)["GIT_PROXY_COMMAND"])
        self.git(folder, "config", "--global", "core.gitProxy", "my-proxy")
        self.assertTrue(self.answer(folder, *listing).refusal)

    def test_a_folder_outside_any_repository_gets_the_hooks_folder_and_the_closed_transport(self):
        outside = self.owned(self.root / "outside")
        outside.mkdir()
        answer = self.answer(outside, "status")
        self.assertEqual("", answer.refusal)
        self.assertEqual(["core.hookspath", "protocol.ext.allow", "protocol.file.allow"],
                         [key for key, _ in answer.settings])

    def test_saw_prints_it_in_the_classify_answer(self):
        folder = self.plain_folder("plain")
        printed = io.StringIO()
        with redirect_stdout(printed):
            cli.main(["govern", "classify", "--json", "--tool", "git", "--repo", str(folder), "--", "status"])
        document = json.loads(printed.getvalue())
        self.assertEqual("schema_version", next(iter(document)))
        self.assertFalse(document["checked"])
        self.assertEqual(["core.hookspath", "protocol.ext.allow", "protocol.file.allow"],
                         [setting["key"] for setting in document["run_with"]["settings"]])

    def test_a_refused_command_is_checked_with_the_reason(self):
        folder = self.plain_folder("plain")
        body, _ = govern.classify(str(folder), "git", ["--git-dir", str(self.root / "no-such"), "status"],
                                  dict(os.environ))
        self.assertTrue(body["checked"])
        self.assertTrue(body["reason"])
        self.assertNotIn("run_with", body)


if __name__ == "__main__":
    unittest.main()
