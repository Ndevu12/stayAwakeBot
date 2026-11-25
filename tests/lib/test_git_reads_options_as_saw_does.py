#!/usr/bin/env python3
"""saw reads the options of a command it checks the way the git under test reads them: every option
git takes a value for is one saw skips the value of, and the hooks folder compares by its
filesystem's own rules."""
from __future__ import annotations

import re
import subprocess
import unicodedata
import unittest

from stayawake.lib.git import incoming, query
from tests.support.gitrepo import GitSandbox


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
        match = _OPTION_LINE.match(line)
        if not match or not (match.group("short") or match.group("long")):
            continue
        kind = "required" if match.group("required") else ("optional" if match.group("optional") else "none")
        for name in (match.group("short"), match.group("long")):
            if name:
                found[name.replace("--[no-]", "--")] = kind
    return found


class TheOptionsGitTakesAValueFor(GitSandbox):

    def test_a_usage_text_is_read_option_by_option(self):
        self.assertEqual(options_in_usage(_USAGE_SAMPLE), {
            "-n": "none", "--stat": "none", "--compact-summary": "none", "--log": "optional", "-e": "none",
            "--edit": "none", "--cleanup": "required", "-s": "required", "--strategy": "required",
            "-C": "required", "--empty": "required", "-j": "optional", "--jobs": "optional",
            "--no-verify": "none"})

    def test_every_option_the_git_under_test_lists_is_read_as_it_reads_it(self):
        repo = self.new_repo()
        for sub, taking_a_word in incoming._OPTIONS_TAKING_THE_NEXT_WORD.items():
            usage = subprocess.run(["git", "-C", str(repo), sub, "--help-all"], capture_output=True, text=True,
                                   stdin=subprocess.DEVNULL).stdout
            listed = options_in_usage(usage)
            with self.subTest(sub=sub):
                self.assertTrue(listed, f"git {sub} listed no options")
                self.assertEqual(sorted(name for name, kind in listed.items()
                                        if kind == "required" and name not in taking_a_word), [])
                self.assertEqual(sorted(name for name, kind in listed.items()
                                        if kind != "required" and name in taking_a_word), [])


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
