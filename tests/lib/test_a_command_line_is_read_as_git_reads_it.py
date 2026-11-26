#!/usr/bin/env python3
"""Every spelling of a git or gh command that brings files in is read as one."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

from stayawake import cli
from stayawake.lib.git import command_line
from stayawake.utils import exitcodes
from tests.support.gitrepo import GitSandbox

_HERE = Path("/work/repo")


def _read(*args: str, aliases: dict[str, str] | None = None, tool: str = "git") -> command_line.Reading:
    table = aliases or {}
    return command_line.read(tool, list(args), _HERE, lambda _folder, name: table.get(name))


class TheGlobalOptionsAreReadAsGitReadsThem(GitSandbox):

    def test_every_option_that_takes_a_value_takes_one(self):
        for option in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--shallow-file",
                       "--attr-source"):
            with self.subTest(option=option):
                subcommand = "status" if option in ("--git-dir", "--work-tree") else "pull"
                reading = _read(option, "HEAD", subcommand)
                self.assertTrue(reading.readable, reading.reason)
                self.assertEqual(reading.subcommand, subcommand)

    def test_the_options_written_with_their_value_are_read(self):
        for option in ("--namespace=n", "--config-env=a=B", "--attr-source=HEAD", "--exec-path=/x"):
            with self.subTest(option=option):
                self.assertEqual((_read(option, "pull").subcommand, _read(option, "pull").kind), ("pull", "pull"))

    def test_the_flags_take_no_value(self):
        for flag in ("-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--bare",
                     "--literal-pathspecs", "--no-literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
                     "--icase-pathspecs", "--no-optional-locks", "--no-advice"):
            with self.subTest(flag=flag):
                self.assertEqual(_read(flag, "pull").kind, "pull")

    def test_an_option_git_does_not_know_is_not_guessed(self):
        for line in (("--super-prefix", "x", "pull"), ("--frobnicate", "pull"), ("-Cx", "pull"), ("--", "pull")):
            with self.subTest(line=line):
                reading = _read(*line)
                self.assertFalse(reading.readable)
                self.assertFalse(reading.brings_files)

    def test_a_missing_value_is_not_guessed(self):
        self.assertFalse(_read("--attr-source").readable)

    def test_version_help_and_queries_bring_nothing(self):
        for line in (("--version",), ("-v",), ("--help", "pull"), ("--exec-path",), ("--html-path",), ("--list-cmds=main",)):
            with self.subTest(line=line):
                reading = _read(*line)
                self.assertTrue(reading.readable)
                self.assertFalse(reading.brings_files)

    def test_the_folder_follows_every_c(self):
        self.assertEqual(_read("-C", "a", "-C", "", "-C", "b", "pull").folder, _HERE / "a" / "b")

    def test_a_command_naming_its_own_repository_is_unreadable(self):
        self.assertFalse(_read("--git-dir", "/elsewhere/.git", "pull").readable)
        self.assertFalse(_read("--work-tree=/elsewhere", "fetch").readable)
        self.assertTrue(_read("--git-dir", "/elsewhere/.git", "status").readable)


class AliasesAreExpandedAsGitExpandsThem(GitSandbox):

    def test_an_alias_for_a_pull_is_a_pull(self):
        reading = _read("p", "--rebase", aliases={"p": "pull origin"})
        self.assertEqual((reading.subcommand, reading.kind, reading.rest), ("pull", "pull", ("origin", "--rebase")))

    def test_an_alias_through_an_alias_is_followed(self):
        self.assertEqual(_read("up", aliases={"up": "sync", "sync": "fetch --all"}).kind, "fetch")

    def test_an_alias_never_hides_a_command_that_brings_files(self):
        self.assertEqual(_read("pull", aliases={"pull": "status"}).kind, "pull")

    def test_an_alias_that_cannot_be_read_is_not_guessed(self):
        for aliases in ({"x": "!git pull"}, {"x": "x"}, {"x": "y", "y": "x"}, {"x": "pull 'unclosed"}, {"x": "-c a=b pull"}):
            with self.subTest(aliases=aliases):
                self.assertFalse(_read("x", aliases=aliases).readable)

    def test_an_alias_set_on_the_command_line_is_followed(self):
        self.assertEqual(_read("-c", "alias.x=pull origin", "x").kind, "pull")
        self.assertEqual(_read("-c", "Alias.X=fetch", "x", aliases={"x": "status"}).kind, "fetch")

    def test_configuration_that_could_change_aliases_is_not_guessed(self):
        for line in (("-c", "include.path=/elsewhere", "x"), ("-c", "includeIf.onbranch:main.path=f", "x"),
                     ("--config-env", "alias.x=VALUE", "x"), ("--config-env=alias.x=VALUE", "x")):
            with self.subTest(line=line):
                self.assertFalse(_read(*line).readable)

    def test_gh_commands_that_bring_files_are_known(self):
        self.assertEqual(_read("pr", "checkout", "12", tool="gh").kind, "gh")
        self.assertEqual(_read("pr", "-R", "owner/repo", "checkout", "12", tool="gh").kind, "gh")
        self.assertEqual(_read("--repo", "owner/repo", "release", "download", tool="gh").kind, "gh")
        self.assertIsNone(_read("pr", "list", tool="gh").kind)


class SawGovernClassifyAnswers(GitSandbox):

    def _classify(self, repo: Path, *args: str) -> tuple[int, dict]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["govern", "classify", "--json", "--tool", "git", "--repo", str(repo), "--", *args])
        return code, json.loads(out.getvalue())

    def test_an_attribute_source_does_not_hide_a_pull(self):
        repo = self.new_repo()
        code, body = self._classify(repo, "--attr-source", "HEAD", "pull")
        self.assertEqual(code, exitcodes.CLEAN)
        self.assertEqual((body["readable"], body["subcommand"], body["brings_files"], body["checked"]),
                         (True, "pull", True, True))

    def test_a_repository_alias_is_read_from_the_folder(self):
        repo = self.new_repo()
        self.git(repo, "config", "alias.get", "pull --ff-only")
        body = self._classify(repo, "get")[1]
        self.assertEqual((body["subcommand"], body["brings_files"], body["folder"]), ("pull", True, str(repo)))

    def test_an_unreadable_line_says_why(self):
        code, body = self._classify(self.new_repo(), "--frobnicate", "pull")
        self.assertEqual(code, exitcodes.INCOMPLETE)
        self.assertEqual((body["readable"], body["checked"]), (False, False))
        self.assertIn("--frobnicate", body["reason"])


class PrepareChecksWhatTheReaderReads(GitSandbox):

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("open")
        self.write(self.repo, "keep.txt", "already\n")
        self.base = self.commit(self.repo, "start")
        self.git(self.repo, "checkout", "-q", "-b", "next")
        self.write(self.repo, "arrived.txt", "from next\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", "main")
        self.git(self.repo, "config", "alias.co", "checkout")

    def test_every_spelling_of_a_checkout_is_checked_first(self):
        for line in (("--attr-source", "HEAD", "checkout", "next"), ("co", "next"),
                     ("-c", "alias.go=checkout", "go", "next"), ("--no-advice", "-P", "checkout", "next")):
            with self.subTest(line=line):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = cli.main(["govern", "prepare", "--json", "--repo", str(self.repo),
                                     "--into", str(self.root / "holding"), "--tool", "git", "--", *line])
                body = json.loads(out.getvalue())
                self.assertEqual(code, exitcodes.CLEAN, body)
                self.assertIn("scan", body)
                self.assertEqual(self.rev(self.repo), self.base)
