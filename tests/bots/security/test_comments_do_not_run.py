#!/usr/bin/env python3
"""A construct written in a comment does not execute, so it is not an execution sink.

`// never use eval() here` marked a file as obfuscated — a comment WARNING against the thing was
read as the thing. So did commented-out code, which is the most ordinary content in a repository.

Strings are deliberately still read: an obfuscator assembles `'ev'+'al'` inside one, so blanking
them would remove real signal rather than noise.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security.obfuscation import analyze_file


class TestACommentIsNotCode(unittest.TestCase):
    CLEAN = {
        "a comment warning against eval": "// never use eval() here\nexport const a = 1;\n",
        "commented-out code": "// const x = eval(userInput);\nconst y = 2;\n",
        "a block comment": "/*\n * eval(payload) is what we must avoid\n */\nconst a = 1;\n",
        "a charcode array in a comment": "// [72,101,108,108,111,44,32,87,111] String.fromCharCode\n"
                                         "const a = 1;\n",
    }

    def test_none_of_them_is_a_finding(self):
        for name, source in self.CLEAN.items():
            with self.subTest(case=name):
                self.assertFalse(analyze_file(source, ".js"))


class TestCodeIsStillRead(unittest.TestCase):
    FIRES = {
        "a real eval": "eval(x);",
        "an eval after a comment": "// this part is fine\neval(x);",
        "a sink assembled inside strings": "global['ev'+'al']('x');",
        "a bracket-key sink": "global['eval']('x');",
        "a charcode shuffler": "const a=[72,101,108,108,111,44,32,87,111];String.fromCharCode(...a);",
    }

    def test_each_still_fires(self):
        for name, source in self.FIRES.items():
            with self.subTest(case=name):
                self.assertTrue(analyze_file(source, ".js"))

    def test_a_sink_mentioned_in_a_string_is_not_blanked_away(self):
        # Strings are kept on purpose — this is where split-token assembly lives.
        self.assertTrue(analyze_file('const s = "eval("; eval(y);', ".js"))


if __name__ == "__main__":
    unittest.main()
