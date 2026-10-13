#!/usr/bin/env python3
"""A home wipe deletes home itself, everything in it, or a walk of it; a named folder inside home
and a whole-line comment are not one."""
from __future__ import annotations

import unittest

from stayawake.bots.security.taint import destructive
from stayawake.bots.security.taint.destructive import detect_destructive


class TestANamedFolderInsideHomeIsNotAWipe(unittest.TestCase):
    def test_shell_projects_that_remove_their_own_folder_are_not_wipes(self):
        for text in (
            "rm -rf ~/.oh-my-zsh",
            "alias xcdd='rm -rf ~/Library/Developer/Xcode/DerivedData/*'",
            '"postCreateCommand": "rm -rf $HOME/.oh-my-zsh && sh -c install.sh"',
            'rm -rf "$HOME/.cache/pip"',
            'rm -rf "${HOME}/.nvm"',
            "find ~/.cache -name '*.tmp' -delete",
            "Remove-Item -Recurse -Force $env:USERPROFILE\\AppData\\Local\\Tool",
        ):
            self.assertIsNone(detect_destructive(text), text)

    def test_scripts_that_remove_a_folder_of_their_own_are_not_wipes(self):
        for text in (
            "rimraf(path.join(os.homedir(), '.cache', 'tool'))",
            "fs.rmSync(path.join(os.homedir(), '.tool'), { recursive: true })",
            "const dir = path.join(os.homedir(), '.tool');\nrimraf(dir)",
            "fs.rmSync(`${os.homedir()}/.tool`, { recursive: true })",
            "rimraf(os.homedir() + '/.tool')",
        ):
            self.assertIsNone(detect_destructive(text), text)


    def test_a_function_that_walks_a_folder_of_its_own_is_not_a_wipe(self):
        text = ("function listCache() { return readdirSync(path.join(os.homedir(), '.cache', 'tool')) }\n"
                "function clean(files) { files.forEach(f => unlinkSync(f)) }\n"
                "const files = listCache(); clean(files)")
        self.assertIsNone(detect_destructive(text))


class TestHomeItselfIsStillAWipe(unittest.TestCase):
    def test_a_function_that_walks_home_is_still_a_wipe(self):
        text = ("function listAll() { return readdirSync(os.homedir()) }\n"
                "function clean(files) { files.forEach(f => unlinkSync(f)) }\n"
                "const files = listAll(); clean(files)")
        self.assertIsNotNone(detect_destructive(text))

    def test_deleting_home_or_everything_in_it_is_found(self):
        for text in (
            "rm -rf ~", "rm -rf ~/", "rm -rf ~/*", "rm -rf ~/.*", "rm -rf $HOME",
            'rm -rf "$HOME"', "rm -rf ${HOME}/*", 'rm -rf "$HOME/"*',
            "rimraf(os.homedir())", "fs.rmSync(os.homedir(), { recursive: true, force: true })",
            "const h = os.homedir();\nrimraf(h)",
            "find ~ -type f -delete", "find ~/ -exec rm -f {} +",
            "Remove-Item -Recurse -Force $env:USERPROFILE", "rm -rf /",
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_home_followed_by_another_path_is_still_home(self):
        self.assertIsNotNone(detect_destructive("rm -rf ~/ build"))

    def test_a_path_that_climbs_back_out_of_a_folder_is_home(self):
        for text in ("rm -rf ~/..", "rm -rf ~/x/..", "rm -rf $HOME/a/../", "rm -rf ~/./"):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_folder_named_only_by_a_variable_is_home(self):
        for text in ("rm -rf $HOME/$TARGET", 'rm -rf "$HOME/${DIR}"'):
            self.assertIsNotNone(detect_destructive(text), text)


class TestOnlyAWholeLineCommentIsNotCode(unittest.TestCase):
    def test_a_comment_line_that_mentions_a_wipe_is_not_one(self):
        for text in ("\t# shell to execute 'sudo rm -rf /' when the prompt is drawn.",
                     "# never run rm -rf ~ here", "#\n## rm -rf ~"):
            self.assertIsNone(detect_destructive(text), repr(text))

    def test_a_wipe_on_the_line_after_a_comment_is_found(self):
        self.assertIsNotNone(detect_destructive("# clean up\nrm -rf ~"))

    def test_a_wipe_after_an_inline_comment_marker_is_still_read(self):
        for text in ("echo done # rm -rf ~", "// ; rm -rf ~", "rem ; rm -rf ~", ":: ; rm -rf ~"):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_only_comment_lines_are_blanked(self):
        kept = ("#!/bin/sh", '#define WIPE system("x")', "x # y", "  code()")
        blanked = ("# a note", "#", "\t## heading")
        for line in kept:
            self.assertEqual(destructive._without_comment_lines(line), line, line)
        for line in blanked:
            self.assertEqual(destructive._without_comment_lines(line).strip(), "", line)


if __name__ == "__main__":
    unittest.main()
