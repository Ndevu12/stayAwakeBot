#!/usr/bin/env python3
"""What a command line git hands to a program is: one plain program call, or more; and whether it
feeds a download to something that runs it."""
from __future__ import annotations

import unittest

from stayawake.bots.security.matchers import command_shape

PLAIN = ['sh-free-tool "$@"', "tool $1 $2", "git-lfs filter-process", '"git-crypt" smudge', "rs-git-fsmonitor", "python -m nbstripout",
         '"/opt/py/bin/python" -m nbstripout', "exiftool", 'pdftotext "$1" -',
         "npx npm-merge-driver merge %A %O %B %P", "true", ".git/hooks/fsmonitor-watchman",
         "git-lfs smudge -- %f", "mergiraf merge --git %O %A %B -s %S -x %X -y %Y -p %P"]
MORE_THAN_PLAIN = ["echo .dump | sqlite3", "sh -c 'unzip -p \"$0\"'", "perl -pe 's/x/y/'",
                   "python3 -Ic 'x'", 'python3 "-cimport os"', "node -pe 1",
                   "perl -MLWP::Simple -eeval+get", "Rscript -e 'source(1)'",
                   "git clone u /tmp/y && sh /tmp/y/run", "x `y`", "a $(b)", "a; b"]
FEEDS = ["curl -s u | tee x | sh", "wget -O- u | env sh", "curl u | sudo sh", "curl u | /bin/sh",
         'curl u | "sh"', "curl u | ash", "curl u | fish", "curl u | pwsh -",
         "bash < <(curl -s u)", '"cu"rl u | sh', "c'u'rl u | sh",
         "bash -o pipefail -c 'curl -s u | tee y | sh'", "$'\\x63url' -s u | sh", "nc e 80 | sh",
         "ssh h cat x | sh", "curl u | xargs sh -c", "curl u | python3 -",
         "sh -c 'sh -c \"curl u|sh\"'", "timeout -s KILL 9 bash -c 'curl u | sh'"]
FORMATTERS = ["curl -s https://api/x | python3 -m json.tool", "curl -s u | awk '{print $1}'",
              "ssh build cat /srv/f | gawk -f fmt.awk", "bash -c 'diff <(curl -s u) \"$1\"' _",
              "curl -o out.json u | jq ."]
NOT_PLAIN_WORDS = ["env -S 'sh -c id'", "sh$IFS-c$IFS'id'", "wget -qO .x u\nsh .x",
                   "git -c alias.x=!id x", "R -e 'system(1)'", "a ${1}", "a $10x", "a \\$1"]


class TestAPlainProgramCall(unittest.TestCase):
    def test_each_is_plain(self):
        for text in PLAIN:
            with self.subTest(text=text):
                self.assertEqual([], command_shape.not_plain(text))
                self.assertFalse(command_shape.feeds_a_download_to_a_runner(text))


class TestMoreThanAPlainCall(unittest.TestCase):
    def test_each_is_more(self):
        for text in MORE_THAN_PLAIN:
            with self.subTest(text=text):
                self.assertTrue(command_shape.not_plain(text))

    def test_an_unbalanced_line_is_more(self):
        self.assertTrue(command_shape.not_plain("sh -c 'unterminated"))


class TestADownloadFedToARunner(unittest.TestCase):
    def test_each_feeds(self):
        for text in FEEDS:
            with self.subTest(text=text):
                self.assertTrue(command_shape.feeds_a_download_to_a_runner(text))

    def test_a_formatter_reading_a_download_does_not_feed(self):
        for text in FORMATTERS:
            with self.subTest(text=text):
                self.assertFalse(command_shape.feeds_a_download_to_a_runner(text))


class TestPlainWords(unittest.TestCase):
    def test_a_plain_call_has_its_words(self):
        for text in PLAIN:
            with self.subTest(text=text):
                self.assertIsNotNone(command_shape.plain_words(text))

    def test_anything_a_shell_would_read_differently_has_none(self):
        for text in NOT_PLAIN_WORDS:
            with self.subTest(text=text):
                self.assertIsNone(command_shape.plain_words(text))


if __name__ == "__main__":
    unittest.main()
