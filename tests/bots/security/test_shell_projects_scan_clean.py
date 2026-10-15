#!/usr/bin/env python3
"""Shell projects and scripts that remove a folder of their own scan clean, and one that deletes
your home folder or everything in it is still reported."""
from __future__ import annotations

import unittest

from stayawake.bots.security.taint import destructive
from stayawake.bots.security.taint.destructive import detect_destructive
from tests.support import samples


class TestProjectsThatRemoveTheirOwnFolderScanClean(unittest.TestCase):
    def test_shell_projects_scan_clean(self):
        for text in (
            samples.joined('r', 'm -rf ~/.oh-my-zsh'),
            samples.joined("alias xcdd='r", "m -rf ~/Library/Developer/Xcode/DerivedData/*'"),
            samples.joined('"postCreateCommand": "r', 'm -rf $H', 'OME/.oh-my-zsh && sh -c install.sh"'),
            samples.joined('r', 'm -rf "$H', 'OME/.cache/pip"'),
            samples.joined('r', 'm -rf "${H', 'OME}/.nvm"'),
            samples.joined('f', "ind ~/.cache -name '*.tmp' -d", 'elete'),
            samples.joined('Remove-Item -Recurse -Force $e', 'nv:USERPROFILE\\AppData\\Local\\Tool'),
        ):
            self.assertIsNone(detect_destructive(text), text)

    def test_scripts_scan_clean(self):
        for text in (
            samples.joined('r', 'imraf(path.join(o', "s.homedir(), '.cache', 'tool'))"),
            samples.joined('fs.r', 'mSync(path.join(o', "s.homedir(), '.tool'), { recursive: true })"),
            samples.joined('const dir = path.join(o', "s.homedir(), '.tool');\nr", 'imraf(dir)'),
            samples.joined('fs.r', 'mSync(`${o', 's.homedir()}/.tool`, { recursive: true })'),
            samples.joined('r', 'imraf(o', "s.homedir() + '/.tool')"),
        ):
            self.assertIsNone(detect_destructive(text), text)

    def test_a_cleanup_of_a_folder_of_their_own_scans_clean(self):
        text = (samples.joined('function listCache() { return r', 'eaddirSync(path.join(o', "s.homedir(), '.cache', 'tool')) }\nfunction clean(files) { files.forEach(f => u", 'nlinkSync(f)) }\nconst files = listCache(); clean(files)'))
        self.assertIsNone(detect_destructive(text))


class TestDeletingYourHomeFolderIsReported(unittest.TestCase):
    def test_a_cleanup_of_your_home_folder_is_reported(self):
        text = (samples.joined('function listAll() { return r', 'eaddirSync(o', 's.homedir()) }\nfunction clean(files) { files.forEach(f => u', 'nlinkSync(f)) }\nconst files = listAll(); clean(files)'))
        self.assertIsNotNone(detect_destructive(text))

    def test_deleting_your_home_folder_or_everything_in_it_is_reported(self):
        for text in (
            samples.joined('r', 'm -rf ~'), samples.joined('r', 'm -rf ~/'), samples.joined('r', 'm -rf ~/*'), samples.joined('r', 'm -rf ~/.*'), samples.joined('r', 'm -rf $H', 'OME'),
            samples.joined('r', 'm -rf "$H', 'OME"'), samples.joined('r', 'm -rf ${H', 'OME}/*'), samples.joined('r', 'm -rf "$H', 'OME/"*'),
            samples.joined('r', 'imraf(o', 's.homedir())'), samples.joined('fs.r', 'mSync(o', 's.homedir(), { recursive: true, force: true })'),
            samples.joined('const h = o', 's.homedir();\nr', 'imraf(h)'),
            samples.joined('f', 'ind ~ -type f -d', 'elete'), samples.joined('f', 'ind ~/ -e', 'xec rm -f {} +'),
            samples.joined('Remove-Item -Recurse -Force $e', 'nv:USERPROFILE'), samples.joined('r', 'm -rf /'),
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_your_home_folder_among_other_paths_is_reported(self):
        self.assertIsNotNone(detect_destructive(samples.joined('r', 'm -rf ~/ build')))

    def test_every_path_that_names_your_home_folder_is_reported(self):
        for text in (samples.joined('r', 'm -rf ~/..'), samples.joined('r', 'm -rf ~/x/..'), samples.joined('r', 'm -rf $H', 'OME/a/../'), samples.joined('r', 'm -rf ~/./')):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_folder_chosen_when_the_script_runs_is_reported(self):
        for text in (samples.joined('r', 'm -rf $H', 'OME/$TARGET'), samples.joined('r', 'm -rf "$H', 'OME/${DIR}"')):
            self.assertIsNotNone(detect_destructive(text), text)


class TestAScriptIsJudgedByItsCode(unittest.TestCase):
    def test_a_project_that_mentions_a_wipe_in_a_comment_scans_clean(self):
        for text in (samples.joined("\t# shell to execute 'sudo r", "m -rf /' when the prompt is drawn."),
                     samples.joined('# never run r', 'm -rf ~ here'), samples.joined('#\n## r', 'm -rf ~')):
            self.assertIsNone(detect_destructive(text), repr(text))

    def test_a_wipe_after_a_comment_is_reported(self):
        self.assertIsNotNone(detect_destructive(samples.joined('# clean up\nr', 'm -rf ~')))

    def test_a_wipe_sharing_a_line_with_a_comment_is_reported(self):
        for text in (samples.joined('echo done # r', 'm -rf ~'), samples.joined('// ; r', 'm -rf ~'), samples.joined('rem ; r', 'm -rf ~'), samples.joined(':: ; r', 'm -rf ~')):
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
