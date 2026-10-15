#!/usr/bin/env python3
"""A command that removes the files of one exact name across home is a cleanup; a walk that removes
everything, a pattern, what a variable names, a folder, or what a search found is still a home wipe."""
from __future__ import annotations

import unittest

from stayawake.bots.security.taint.destructive import detect_destructive


class TestRemovingOneNamedFileAcrossHomeIsNotAWipe(unittest.TestCase):
    def test_removing_one_named_file_across_home_scans_clean(self):
        for text in (
            "find ~ -name '.DS_Store' -type f -delete",
            'find "$HOME" -type f -name .DS_Store -delete',
            "find ${HOME} -iname 'Thumbs.db' -exec rm -f {} +",
            "find ~ -name .DS_Store -exec rm {} \\;",
            "find ~ -name .DS_Store -print0 | xargs -0 rm -f",
            "find ~ -name '.DS_Store' -type f -delete 2>/dev/null",
            "#!/bin/sh\nfind ~ -name '.DS_Store' -type f -delete\n",
        ):
            self.assertIsNone(detect_destructive(text), text)

    def test_a_script_that_runs_the_same_cleanup_scans_clean(self):
        text = ("const { execSync } = require('child_process');\n"
                "function tidy() { execSync(\"find ~ -name '.DS_Store' -type f -delete\") }\n"
                "tidy()")
        self.assertIsNone(detect_destructive(text))


class TestAWalkThatRemovesMoreThanOneNameIsStillAWipe(unittest.TestCase):
    def test_removing_everything_a_pattern_or_a_variable_names_is_found(self):
        for text in (
            "find ~ -type f -delete",
            'find "$HOME" -depth -type d -empty -delete',
            "find ~ -name '*' -delete",
            "find ~ -name '*' -type f -delete",
            "find ~ -iname '*.doc*' -delete",
            "find ~ -name '[a-z]*' -delete",
            'find ~ -name "$PATTERN" -delete',
            "find ~ -regex '.*' -delete",
            "find ~ -name *.log -type f -delete",
            'find ~ -name "*.log" -type f -delete',
            'find ~ -name "$PATTERN" -type f -delete',
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_removing_a_named_folder_across_home_is_found(self):
        for text in (
            "find ~ -name .ssh -prune -exec rm -rf {} +",
            "find ~ -name Documents -exec rm -rf {} +",
            "find ~ -type d -name node_modules -prune -exec rm -rf {} +",
            "find ~ -name .gnupg -exec rm -r {} \\;",
            'find "$HOME" -name .DS_Store -delete',
            'find "$HOME" -name ".aws" -print -delete',
            "find ~ -name .ssh -print0 | xargs -0 rm -rf",
            "find ~ -name .ssh -exec find {} -type f -delete \\;",
            "find ~ -name .ssh -exec sh -c 'find \"$1\" -type f -delete' _ {} \\;",
            "find ~ -name .ssh -print0 | xargs -0 -I{} find {} -delete",
            'for d in $(find ~ -name .ssh); do find "$d" -delete; done',
            "find ~ -name .ssh -exec rm -f {} + -delete",
            "find ~ -name .ssh -delete -type f",
            "find ~ -name node_modules -type d -delete",
            "find ~ -name .ssh -exec rimraf {} +",
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_named_search_whose_results_the_script_removes_is_found(self):
        for remover in ("rimraf.sync(d)", "fs.unlinkSync(d)", "execSync('find \"' + d + '\" -delete')"):
            text = ("const { execSync } = require('child_process');\n"
                    "const fs = require('fs');\n"
                    "const rimraf = require('rimraf');\n"
                    "function findKeys() { return execSync(\"find ~ -name '.ssh'\").toString().split('\\n') }\n"
                    f"function removeAll(dirs) {{ dirs.forEach(d => {remover}) }}\n"
                    "const keys = findKeys();\n"
                    "removeAll(keys);")
            self.assertIsNotNone(detect_destructive(text), remover)

    def test_a_named_file_widened_by_or_or_not_is_found(self):
        for text in (
            "find ~ ! -name .DS_Store -type f -delete",
            "find ~ \\! -name .DS_Store -type f -delete",
            "find ~ -not -name .DS_Store -type f -delete",
            "find ~ -name .DS_Store -o -type f -delete",
            "find ~ -name .DS_Store -or -type f -delete",
            "find ~ -name node_modules -prune -o -delete",
            "find ~ -name .DS_Store -exec rm -f {} ';' -o -exec rm -f {} +",
            "find ~ -name .DS_Store -exec rm -f {} \\; -o -delete",
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_cleanup_beside_a_wipe_is_found(self):
        for text in (
            "find ~ -name .DS_Store -type f -delete; rm -rf ~",
            "find ~ -name .DS_Store -type f -delete\nfind ~ -type f -delete",
            "find ~ -type f -delete; find . -name .DS_Store -print",
            "find ~ -type f -delete | find . -name .DS_Store -print",
            "find ~ -name .DS_Store -type f -delete; rm -f ~/* ~/*/*",
        ):
            self.assertIsNotNone(detect_destructive(text), text)

    def test_a_named_file_beside_a_scripts_walk_of_home_is_found(self):
        text = "klaw(os.homedir() /* -name .keep */).on('data', f => unlinkSync(f.path))"
        self.assertIsNotNone(detect_destructive(text))


if __name__ == "__main__":
    unittest.main()
