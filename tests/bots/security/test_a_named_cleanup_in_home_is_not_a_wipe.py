#!/usr/bin/env python3
"""A command that removes the files of one exact name across home is a cleanup; a walk that removes
everything, a pattern, what a variable names, a folder, or what a search found is still a home wipe."""
from __future__ import annotations

import unittest

from stayawake.bots.security.taint.destructive import detect_destructive
from tests.support import samples


class TestRemovingOneNamedFileAcrossHomeIsNotAWipe(unittest.TestCase):
    def test_removing_one_named_file_across_home_scans_clean(self):
        for text in (
            samples.joined('f', "ind ~ -name '.DS_Store' -type f -d", 'elete'),
            samples.joined('f', 'ind "$H', 'OME" -type f -name .DS_Store -d', 'elete'),
            samples.joined('f', 'ind ${H', "OME} -iname 'Thumbs.db' -e", 'xec rm -f {} +'),
            samples.joined('f', 'ind ~ -name .DS_Store -e', 'xec rm {} \\;'),
            samples.joined('f', 'ind ~ -name .DS_Store -print0 | xargs -0 r', 'm -f'),
            samples.joined('f', "ind ~ -name '.DS_Store' -type f -d", 'elete 2>/dev/null'),
            samples.joined('#!/bin/sh\nf', "ind ~ -name '.DS_Store' -type f -d", 'elete\n'),
        ):
            self.assertIsNone(detect_destructive(text), text)

    def test_a_script_that_runs_the_same_cleanup_scans_clean(self):
        text = (samples.joined('const { execSync } = require(\'child_process\');\nfunction tidy() { execSync("f', "ind ~ -name '.DS_Store' -type f -d", 'elete") }\ntidy()'))
        self.assertIsNone(detect_destructive(text))


class TestAWalkThatRemovesMoreThanOneNameIsStillAWipe(unittest.TestCase):
    def test_removing_everything_a_pattern_or_a_variable_names_is_found(self):
        for text in (
            samples.joined('f', 'ind ~ -type f -d', 'elete'),
            samples.joined('f', 'ind "$H', 'OME" -depth -type d -empty -d', 'elete'),
            samples.joined('f', "ind ~ -name '*' -d", 'elete'),
            samples.joined('f', "ind ~ -name '*' -type f -d", 'elete'),
            samples.joined('f', "ind ~ -iname '*.doc*' -d", 'elete'),
            samples.joined('f', "ind ~ -name '[a-z]*' -d", 'elete'),
            samples.joined('f', 'ind ~ -name "$PATTERN" -d', 'elete'),
            samples.joined('f', "ind ~ -regex '.*' -d", 'elete'),
            samples.joined('f', 'ind ~ -name *.log -type f -d', 'elete'),
            samples.joined('f', 'ind ~ -name "*.log" -type f -d', 'elete'),
            samples.joined('f', 'ind ~ -name "$PATTERN" -type f -d', 'elete'),
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_removing_a_named_folder_across_home_is_found(self):
        for text in (
            samples.joined('f', 'ind ~ -name .ssh -prune -e', 'xec rm -rf {} +'),
            samples.joined('f', 'ind ~ -name Documents -e', 'xec rm -rf {} +'),
            samples.joined('f', 'ind ~ -type d -name node_modules -prune -e', 'xec rm -rf {} +'),
            samples.joined('f', 'ind ~ -name .gnupg -e', 'xec rm -r {} \\;'),
            samples.joined('f', 'ind "$H', 'OME" -name .DS_Store -d', 'elete'),
            samples.joined('f', 'ind "$H', 'OME" -name ".aws" -print -d', 'elete'),
            samples.joined('f', 'ind ~ -name .ssh -print0 | xargs -0 r', 'm -rf'),
            samples.joined('f', 'ind ~ -name .ssh -exec find {} -type f -d', 'elete \\;'),
            samples.joined('f', 'ind ~ -name .ssh -exec sh -c \'find "$1" -type f -d', "elete' _ {} \\;"),
            samples.joined('f', 'ind ~ -name .ssh -print0 | xargs -0 -I{} find {} -d', 'elete'),
            samples.joined('for d in $(f', 'ind ~ -name .ssh); do find "$d" -d', 'elete; done'),
            samples.joined('f', 'ind ~ -name .ssh -e', 'xec rm -f {} + -d', 'elete'),
            samples.joined('f', 'ind ~ -name .ssh -d', 'elete -type f'),
            samples.joined('f', 'ind ~ -name node_modules -type d -d', 'elete'),
            samples.joined('f', 'ind ~ -name .ssh -exec r', 'imraf {} +'),
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_named_search_whose_results_the_script_removes_is_found(self):
        find_home = samples.joined("fi", "nd ~ -name '.ssh'")
        for remover in (samples.joined('r', 'imraf.sync(d)'), samples.joined('fs.u', 'nlinkSync(d)'), samples.joined('execSync(\'find "\' + d + \'" -d', "elete')")):
            text = ("const { execSync } = require('child_process');\n"
                    "const fs = require('fs');\n"
                    "const rimraf = require('rimraf');\n"
                    f"function findKeys() {{ return execSync(\"{find_home}\").toString().split('\\n') }}\n"
                    f"function removeAll(dirs) {{ dirs.forEach(d => {remover}) }}\n"
                    "const keys = findKeys();\n"
                    "removeAll(keys);")
            self.assertIsNotNone(detect_destructive(text), remover)

    def test_a_named_file_widened_by_or_or_not_is_found(self):
        for text in (
            samples.joined('f', 'ind ~ ! -name .DS_Store -type f -d', 'elete'),
            samples.joined('f', 'ind ~ \\! -name .DS_Store -type f -d', 'elete'),
            samples.joined('f', 'ind ~ -not -name .DS_Store -type f -d', 'elete'),
            samples.joined('f', 'ind ~ -name .DS_Store -o -type f -d', 'elete'),
            samples.joined('f', 'ind ~ -name .DS_Store -or -type f -d', 'elete'),
            samples.joined('f', 'ind ~ -name node_modules -prune -o -d', 'elete'),
            samples.joined('f', 'ind ~ -name .DS_Store -e', "xec rm -f {} ';' -o -e", 'xec rm -f {} +'),
            samples.joined('f', 'ind ~ -name .DS_Store -e', 'xec rm -f {} \\; -o -d', 'elete'),
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_cleanup_beside_a_wipe_is_found(self):
        for text in (
            samples.joined('f', 'ind ~ -name .DS_Store -type f -d', 'elete; r', 'm -rf ~'),
            samples.joined('f', 'ind ~ -name .DS_Store -type f -d', 'elete\nf', 'ind ~ -type f -d', 'elete'),
            samples.joined('f', 'ind ~ -type f -d', 'elete; find . -name .DS_Store -print'),
            samples.joined('f', 'ind ~ -type f -d', 'elete | find . -name .DS_Store -print'),
            samples.joined('f', 'ind ~ -name .DS_Store -type f -d', 'elete; r', 'm -f ~/* ~/*/*'),
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_named_file_beside_a_scripts_walk_of_home_is_found(self):
        text = samples.joined('k', 'law(o', "s.homedir() /* -name .keep */).on('data', f => u", 'nlinkSync(f.path))')
        self.assertIsNotNone(detect_destructive(text))


if __name__ == "__main__":
    unittest.main()
