#!/usr/bin/env python3
"""saw reads the options of a command it checks the way the git under test reads them: every option
git takes a value for is one saw skips the value of, and the hooks folder compares by its
filesystem's own rules."""
from __future__ import annotations

import re
import subprocess
import unicodedata
import unittest

from stayawake.lib.git import query, subcommand_options
from tests.support.gitrepo import GitSandbox


_USAGE_LINE = re.compile(r"^(?:usage|\s*or):\s+git\s+\S+\s*(?P<rest>.*)$")
_LEADING_OPTION = re.compile(r"\[-[\w-]+\]")
_NUMBER_LINE = re.compile(r"^\s+-NUM\b")
_OPTION_LINE = re.compile(r"^\s+(?P<short>-\w)?(?:, )?(?P<long>--(?:\[no-\])?\w[\w-]*)?"
                          r"(?P<optional>\[=?[^\]\s]*\])?"
                          r"(?: (?P<required>[<({\[]\S*|\S*[()<>\[\]|]\S*|\.\.\.))?")
_USAGE_SAMPLE = """usage: git merge [<options>] [<commit>...]
   or: git merge --abort

    -n                    do not show a diffstat at the end of the merge
    --[no-]stat           show a diffstat at the end of the merge
    --[no-]compact-summary
                          show a compact-summary at the end of the merge
    --[no-]log[=<n>]      add (at most <n>) entries from shortlog to merge commit message
    -e, --[no-]edit       edit message before committing
    --[no-]cleanup <mode> how to strip spaces and #comments from message
    -s, --strategy <strategy>
                          merge strategy to use
    -C <n>                passed to 'git apply'
    --empty (drop|keep|stop)
                          how to handle commits that become empty
    -j, --[no-]jobs[=<n>] number of submodules pulled in parallel
    --no-verify           bypass pre-merge-commit and commit-msg hooks
"""


def options_in_usage(text: str) -> dict[str, str]:
    """Read every option a git usage text lists. Takes the text. Returns each option's name, short and
    long, mapped to required, optional or none for the value it takes."""
    found = {}
    for line in text.splitlines():
        if _NUMBER_LINE.match(line):
            found["-NUM"] = "none"
            continue
        match = _OPTION_LINE.match(line)
        if not match or not (match.group("short") or match.group("long")):
            continue
        kind = "required" if match.group("required") else ("optional" if match.group("optional") else "none")
        for name in (match.group("short"), match.group("long")):
            if name:
                found[name.replace("--[no-]", "--")] = kind
    return found


def words_in_usage(text: str) -> tuple[set[str], set[str]]:
    """Read the word each usage line of a git command starts with, after the options it may take
    first. Takes the usage text. Returns the words, "" for a line with none, and those leading
    options."""
    words: set[str] = set()
    leading: set[str] = set()
    for line in text.splitlines():
        match = _USAGE_LINE.match(line)
        if not match:
            continue
        tokens = match.group("rest").split()
        while tokens and _LEADING_OPTION.fullmatch(tokens[0]):
            leading.add(tokens.pop(0))
        word = tokens[0].strip("[]") if tokens else ""
        words.add(word if re.fullmatch(r"[a-z][a-z-]*", word) else "")
    return words, leading


_GIT_VERSION = subprocess.run(["git", "--version"], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL).stdout.strip()


def _help_all(repo, sub: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *sub.split(), "--help-all"], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL).stdout


class TheOptionsGitTakesAValueFor(GitSandbox):

    def test_a_usage_text_is_read_option_by_option(self):
        self.assertEqual(options_in_usage(_USAGE_SAMPLE), {
            "-n": "none", "--stat": "none", "--compact-summary": "none", "--log": "optional", "-e": "none",
            "--edit": "none", "--cleanup": "required", "-s": "required", "--strategy": "required",
            "-C": "required", "--empty": "required", "-j": "optional", "--jobs": "optional",
            "--no-verify": "none"})

    def test_every_option_the_git_under_test_lists_is_read_as_it_reads_it(self):
        repo = self.new_repo()
        for sub, table in subcommand_options.LISTED.items():
            if not table.lists_its_options or table.echoes_options_it_does_not_take:
                continue
            listed = options_in_usage(_help_all(repo, sub))
            taking_a_word = table.takes_the_next_word
            required = {name for name, kind in listed.items() if kind == "required"}
            with self.subTest(sub=sub, git=_GIT_VERSION):
                self.assertTrue(listed, f"git {sub} listed no options")
                self.assertEqual(sorted(required - taking_a_word), [])
                self.assertEqual(sorted(name for name, kind in listed.items()
                                        if kind != "required" and name in taking_a_word), [])
                self.assertEqual(sorted(name for name, kind in listed.items() if kind == "optional"
                                        and not name.startswith("--")
                                        and name not in table.takes_the_rest_of_its_word), [])
                self.assertEqual(sorted(table.takes_the_rest_of_its_word & required), [])

    def test_every_option_saw_lets_run_as_typed_is_one_git_lists_without_a_value(self):
        repo = self.new_repo()
        for sub, table in subcommand_options.LISTED.items():
            if not table.lists_its_options or table.echoes_options_it_does_not_take:
                continue
            if table.takes_no_word is None:
                continue
            listed = options_in_usage(_help_all(repo, sub))
            with self.subTest(sub=sub):
                self.assertEqual(sorted(name for name, kind in listed.items() if kind == "required"
                                        and name in table.takes_no_word), [])
                self.assertEqual(sorted(name for name, kind in listed.items() if kind != "required"
                                        and name not in table.takes_no_word | table.takes_the_rest_of_its_word),
                                 [])

    def test_every_word_a_command_starts_with_is_one_saw_decides(self):
        repo = self.new_repo()
        decided = {
            "stash": subcommand_options.STASH_WORDS_THAT_BRING_NOTHING
            | subcommand_options.STASH_WORDS_SAW_LEAVES_TO_YOU,
            "worktree": subcommand_options.WORKTREE_WORDS_THAT_BRING_NOTHING
            | subcommand_options.WORKTREE_WORDS_SAW_LEAVES_TO_YOU,
            "submodule": subcommand_options.SUBMODULE_WORDS_THAT_BRING_NOTHING
            | subcommand_options.SUBMODULE_WORDS_SAW_LEAVES_TO_YOU | subcommand_options.SUBMODULE_WORDS_SAW_CHECKS,
        }
        for sub, words in decided.items():
            usage = subprocess.run(["git", "-C", str(repo), sub, "-h"], capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL)
            listed, leading = words_in_usage(usage.stdout + usage.stderr)
            with self.subTest(sub=sub):
                self.assertTrue(listed, f"git {sub} listed no words")
                self.assertEqual(sorted(listed - words - {""}), [])
                self.assertEqual(sorted(leading - {"[--quiet]", "[--cached]"}), [])


class TheHooksFolderComparesByItsFilesystem(GitSandbox):

    def test_case_counts_only_where_the_filesystem_folds_it(self):
        repo = self.new_repo()
        self.git(repo, "config", "core.hooksPath", ".githooks")
        (repo / ".githooks").mkdir()
        changed = (".GitHooks/pre-commit", "src/app.js")
        self.assertEqual(query.hook_files(repo, changed, folds_case=lambda _folder: True), (".GitHooks/pre-commit",))
        self.assertEqual(query.hook_files(repo, changed, folds_case=lambda _folder: False), ())
        self.assertEqual(query.hook_files(repo, (".githooks/pre-commit",), folds_case=lambda _folder: False),
                         (".githooks/pre-commit",))

    def test_composition_counts_only_where_the_filesystem_composes_names(self):
        repo = self.new_repo()
        folder = unicodedata.normalize("NFC", "höoks")
        self.git(repo, "config", "core.hooksPath", folder)
        changed = (unicodedata.normalize("NFD", "höoks") + "/pre-commit",)
        self.assertEqual(query.hook_files(repo, changed, folds_case=lambda _f: False, composes=lambda _f: True),
                         changed)
        self.assertEqual(query.hook_files(repo, changed, folds_case=lambda _f: False, composes=lambda _f: False),
                         ())


if __name__ == "__main__":
    unittest.main()
