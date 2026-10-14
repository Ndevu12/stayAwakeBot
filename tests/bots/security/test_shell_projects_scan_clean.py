#!/usr/bin/env python3
"""Shell projects and scripts that remove a folder of their own scan clean, and one that deletes
your home folder or everything in it is still reported."""
from __future__ import annotations

import unittest

from stayawake.bots.security.taint import destructive
from stayawake.bots.security.taint.destructive import detect_destructive


class TestProjectsThatRemoveTheirOwnFolderScanClean(unittest.TestCase):
    def test_shell_projects_scan_clean(self):
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

    def test_scripts_scan_clean(self):
        for text in (
            "rimraf(path.join(os.homedir(), '.cache', 'tool'))",
            "fs.rmSync(path.join(os.homedir(), '.tool'), { recursive: true })",
            "const dir = path.join(os.homedir(), '.tool');\nrimraf(dir)",
            "fs.rmSync(`${os.homedir()}/.tool`, { recursive: true })",
            "rimraf(os.homedir() + '/.tool')",
        ):
            self.assertIsNone(detect_destructive(text), text)

    def test_a_cleanup_of_a_folder_of_their_own_scans_clean(self):
        text = ("function listCache() { return readdirSync(path.join(os.homedir(), '.cache', 'tool')) }\n"
                "function clean(files) { files.forEach(f => unlinkSync(f)) }\n"
                "const files = listCache(); clean(files)")
        self.assertIsNone(detect_destructive(text))


class TestDeletingYourHomeFolderIsReported(unittest.TestCase):
    def test_a_cleanup_of_your_home_folder_is_reported(self):
        text = ("function listAll() { return readdirSync(os.homedir()) }\n"
                "function clean(files) { files.forEach(f => unlinkSync(f)) }\n"
                "const files = listAll(); clean(files)")
        self.assertIsNotNone(detect_destructive(text))

    def test_deleting_your_home_folder_or_everything_in_it_is_reported(self):
        for text in (
            "rm -rf ~", "rm -rf ~/", "rm -rf ~/*", "rm -rf ~/.*", "rm -rf $HOME",
            'rm -rf "$HOME"', "rm -rf ${HOME}/*", 'rm -rf "$HOME/"*',
            "rimraf(os.homedir())", "fs.rmSync(os.homedir(), { recursive: true, force: true })",
            "const h = os.homedir();\nrimraf(h)",
            "find ~ -type f -delete", "find ~/ -exec rm -f {} +",
            "Remove-Item -Recurse -Force $env:USERPROFILE", "rm -rf /",
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_your_home_folder_among_other_paths_is_reported(self):
        self.assertIsNotNone(detect_destructive("rm -rf ~/ build"))

    def test_every_path_that_names_your_home_folder_is_reported(self):
        for text in ("rm -rf ~/..", "rm -rf ~/x/..", "rm -rf $HOME/a/../", "rm -rf ~/./"):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_folder_chosen_when_the_script_runs_is_reported(self):
        for text in ("rm -rf $HOME/$TARGET", 'rm -rf "$HOME/${DIR}"'):
            self.assertIsNotNone(detect_destructive(text), text)


class TestAScriptIsJudgedByItsCode(unittest.TestCase):
    def test_a_project_that_mentions_a_wipe_in_a_comment_scans_clean(self):
        for text in ("\t# shell to execute 'sudo rm -rf /' when the prompt is drawn.",
                     "# never run rm -rf ~ here", "#\n## rm -rf ~"):
            self.assertIsNone(detect_destructive(text), repr(text))

    def test_a_wipe_after_a_comment_is_reported(self):
        self.assertIsNotNone(detect_destructive("# clean up\nrm -rf ~"))

    def test_a_wipe_sharing_a_line_with_a_comment_is_reported(self):
        for text in ("echo done # rm -rf ~", "// ; rm -rf ~", "rem ; rm -rf ~", ":: ; rm -rf ~"):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_code_lines_reach_the_scan_as_written(self):
        kept = ("#!/bin/sh", '#define WIPE system("x")', "x # y", "  code()")
        blanked = ("# a note", "#", "\t## heading")
        for line in kept:
            self.assertEqual(destructive._without_comment_lines(line), line, line)
        for line in blanked:
            self.assertEqual(destructive._without_comment_lines(line).strip(), "", line)


if __name__ == "__main__":
    unittest.main()
