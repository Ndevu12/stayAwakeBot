#!/usr/bin/env python3
"""A command on saw's direct-run list runs directly when its command line names no program or
command to run and no file to write, each option read the way git reads it. An option git does not
take, or a leading part naming several, sends it to saw. Options that start a program the operator
configured still run directly."""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from stayawake.lib.git import runs_directly, subcommand_options

DOCUMENTED = Path(__file__).resolve().parent / "git_documented_revision_and_diff_options.json"
LOG_FAMILY = ("log", "show", "diff", "rev-list", "whatchanged", "shortlog", "blame")
_TERM = re.compile(r"^(?P<name>-<\w+>|--\[no-\][\w-]+|--?[A-Za-z0-9][\w-]*)(?P<rest>.*)$")


def documented_option(term: str) -> "tuple[str, str] | None":
    """Read one option term of git's documentation. Takes the term, such as `--output=<file>`.
    Returns its name, with `-NUM` for `-<number>`, and required, optional or none for its value."""
    match = _TERM.match(term)
    if not match:
        return None
    name, rest = match.group("name"), match.group("rest")
    if name.startswith("-<"):
        return "-NUM", "none"
    name = name.replace("--[no-]", "--")
    if rest.startswith("["):
        return name, "optional"
    if rest and (rest[0] in "= <:," or not name.startswith("--")):
        return name, "required"
    return name, "none"


class ADirectRunNamesNoProgramAndNoFile(unittest.TestCase):

    def setUp(self):
        made = tempfile.TemporaryDirectory()
        self.addCleanup(made.cleanup)
        self.folder = Path(made.name)

    def _decided(self, *args: str) -> str:
        return runs_directly.decide("git", list(args), self.folder, {})

    def test_a_push_or_ls_remote_naming_a_program_by_a_leading_part_goes_to_saw_whatever_its_target(self):
        for args in (["push", "--e=touch x", "./dst:x"], ["push", "--e=touch x", f"{self.folder}/nodir:y"],
                     ["ls-remote", "--upload-pack=touch x", "../src"], ["ls-remote", "--exec=touch x", "../src"],
                     ["ls-remote", "--u=touch x", "../src"]):
            with self.subTest(args=args):
                self.assertEqual(self._decided(*args), runs_directly.CHECKED_FOR_WHAT_IT_NAMES)
                self.assertEqual(runs_directly.named_by_its_options(args[0], args[1:]), runs_directly.RUNS_A_PROGRAM)

    def test_a_shortened_repository_a_shortened_fetch_or_a_named_socket_goes_to_saw(self):
        bare = self.folder / "bare.git"
        bare.mkdir()
        for args, named in ((["push", f"--rep={bare}", "--all"], None), (["push", "--repo", str(bare), "--all"], None),
                            (["remote", "add", "--fe", "x", str(bare)], runs_directly.FETCHES),
                            (["remote", "add", "-ft", "main", "y", str(bare)], runs_directly.FETCHES),
                            (["credential-cache", f"--socket={bare}/s", "get"], runs_directly.WRITES_A_FILE)):
            with self.subTest(args=args):
                self.assertEqual(self._decided(*args), runs_directly.CHECKED_FOR_WHAT_IT_NAMES)
                self.assertEqual(runs_directly.named_by_its_options(args[0], args[1:]), named)
        resolved = subcommand_options.resolve("push", ["--rep=x", "-o", "y", "--", "z"])
        self.assertEqual((resolved.values("--repo"), resolved.values("--push-option"), resolved.words), (["x"], [], ()))

    def test_a_grep_opening_its_files_in_a_program_goes_to_saw_in_every_form(self):
        for args in (["-O"], ["-Ovim"], ["-iO"], ["-nOvim"], ["-1O"], ["-O", "vim"], ["--open-files-in-pager"],
                     ["--open-files-in-pager=vim"], ["--open"], ["--open-f=vim"], ["-e", "x", "-O"],
                     ["-e", "--", "-Ovim"], ["-n", "x", "--", "-O"], ["--o=vim"]):
            with self.subTest(args=args):
                self.assertEqual(self._decided("grep", *args, "x"), runs_directly.CHECKED_FOR_WHAT_IT_NAMES)

    def test_saw_reads_a_grep_as_git_reads_it(self):
        for args, named in ((["-O"], runs_directly.RUNS_A_PROGRAM), (["-nOvim"], runs_directly.RUNS_A_PROGRAM),
                            (["-e", "--", "-Ovim"], runs_directly.RUNS_A_PROGRAM),
                            (["-e", "-O", "x"], runs_directly.RUNS_A_PROGRAM),
                            (["--open-f=vim", "x"], runs_directly.RUNS_A_PROGRAM),
                            (["--o=vim", "x"], runs_directly.RUNS_A_PROGRAM),
                            (["-eO", "x"], None), (["-n", "x", "--", "-O"], None), (["-C3", "-n", "x"], None)):
            with self.subTest(args=args):
                self.assertEqual(runs_directly.named_by_its_options("grep", args), named)

    def test_a_path_named_like_a_written_file_after_the_separator_goes_to_saw_and_saw_reads_it_as_a_path(self):
        self.assertEqual(self._decided("log", "-1", "--", "--output=x"), runs_directly.CHECKED_FOR_WHAT_IT_NAMES)
        self.assertIsNone(runs_directly.named_by_its_options("log", ["-1", "--", "--output=x"]))

    def test_an_option_that_writes_a_file_goes_to_saw(self):
        for args in (["log", "--out=x"], ["show", "--outp", "x"], ["diff", "--output=x"], ["range-diff", "--output=x"],
                     ["repack", "--filter-to=../x"], ["gc", "--expire-to", "../x"], ["credential-store", "--file=x", "get"]):
            with self.subTest(args=args):
                self.assertEqual(self._decided(*args), runs_directly.CHECKED_FOR_WHAT_IT_NAMES)
                self.assertEqual(runs_directly.named_by_its_options(args[0], args[1:]), runs_directly.WRITES_A_FILE)

    def test_an_option_git_does_not_take_or_an_ambiguous_leading_part_goes_to_saw(self):
        for args in (["status", "--bogus"], ["status", "-Z"], ["log", "--bogus"], ["notes", "add", "--bogus"],
                     ["commit", "--a", "-m", "x"], ["branch", "--no-such"]):
            with self.subTest(args=args):
                self.assertEqual(self._decided(*args), runs_directly.CHECKED_FOR_WHAT_IT_NAMES)
                self.assertEqual(runs_directly.named_by_its_options(args[0], args[1:]), runs_directly.NOT_READ)

    def test_a_command_off_the_direct_run_list_is_asked(self):
        self.assertEqual(runs_directly.named_by_its_options("checkout", ["main"]), runs_directly.NOT_READ)

    def test_options_that_start_a_program_the_operator_configured_still_run_directly(self):
        for args in (["commit", "-S", "-m", "x"], ["commit", "-e", "-m", "x"], ["tag", "-a", "v1", "-m", "x"],
                     ["log", "--show-signature"], ["diff", "--ext-diff"], ["diff", "--textconv"], ["status"], ["log"],
                     ["diff"], ["status", "-sb"], ["log", "--oneline", "-5", "--format=%H"], ["commit", "--amend", "--no-edit"],
                     ["notes", "add", "-m", "x"], ["reflog", "--date=iso"], ["rev-parse", "--show-toplevel"],
                     ["shortlog", "-sn"], ["blame", "-L", "1,2", "--", "f"], ["status", "--help-all"]):
            with self.subTest(args=args):
                self.assertEqual(self._decided(*args), runs_directly.RUNS_AS_TYPED)
                self.assertIsNone(runs_directly.named_by_its_options(args[0], args[1:]))

    def test_every_direct_run_subcommand_lists_every_option_git_takes_or_is_read_by_its_own_rule(self):
        known = runs_directly.tables()
        for sub in known["subcommands_that_bring_no_files"]:
            with self.subTest(sub=sub):
                listed = subcommand_options.LISTED.get(sub)
                self.assertTrue(sub in known["subcommands_read_by_their_own_rule"]
                                or (listed is not None and listed.takes_no_word is not None))

    def test_every_value_taking_option_the_documentation_lists_is_classified_for_the_log_family(self):
        captured = json.loads(DOCUMENTED.read_text(encoding="utf-8"))["tags"]
        self.assertEqual(sorted(captured), ["v2.34.0", "v2.56.1"])
        for tag, files in captured.items():
            for file, terms in files.items():
                options = [found for found in map(documented_option, terms) if found and found[1] != "none"]
                self.assertTrue(options, f"{file} at {tag}")
                for name, _value in options:
                    for sub in LOG_FAMILY:
                        listed = subcommand_options.LISTED[sub]
                        with self.subTest(tag=tag, file=file, option=name, sub=sub):
                            self.assertIn(name, listed.takes_the_next_word | listed.takes_the_rest_of_its_word
                                          | listed.takes_no_word)

    def test_a_documented_term_is_read_by_name_and_value(self):
        self.assertEqual(documented_option("--output=<file>"), ("--output", "required"))
        self.assertEqual(documented_option("--stat[=<width>]"), ("--stat", "optional"))
        self.assertEqual(documented_option("-U<n>"), ("-U", "required"))
        self.assertEqual(documented_option("-n <number>"), ("-n", "required"))
        self.assertEqual(documented_option("-<number>"), ("-NUM", "none"))
        self.assertEqual(documented_option("--[no-]rename-empty"), ("--rename-empty", "none"))


if __name__ == "__main__":
    unittest.main()
