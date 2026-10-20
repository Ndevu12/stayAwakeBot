#!/usr/bin/env python3
"""The hook's suspicious-signal warning names what it found and where, as its infected warning does:
confirmed findings first, at most five, then how many it left out and the command that lists them."""
from __future__ import annotations

import contextlib
import io
import unittest
from types import SimpleNamespace

from stayawake.bots.security import hook
from stayawake.bots.security.found import left_out_line, what_it_is

_GHOST = ("ghost-package", "supply-chain-dep")


def _finding(path: str, confidence: str = "heuristic"):
    return SimpleNamespace(signature_id=_GHOST[0], category=_GHOST[1], path=path, line=None,
                           commit_sha="", confidence=confidence)


def _suspicious(*findings):
    return SimpleNamespace(infected=False, error="", suspicious=True, residue=False,
                           findings=list(findings))


def _tell(result) -> tuple[int | None, str]:
    printed = io.StringIO()
    with contextlib.redirect_stderr(printed):
        code = hook._tell(result, "repo", "saw scan repo", "repo")
    return code, printed.getvalue()


class TestASuspiciousWarningNamesWhatItFound(unittest.TestCase):
    def test_it_names_each_finding_and_where_it_is(self):
        code, said = _tell(_suspicious(_finding("node_modules/dropped/package.json")))
        self.assertEqual(code, 0)
        self.assertIn("1 suspicious signal(s)", said)
        self.assertIn(f"{what_it_is(*_GHOST)}  —  node_modules/dropped/package.json", said)
        self.assertIn("saw scan repo", said)

    def test_past_five_it_says_how_many_it_left_out_and_how_to_see_them(self):
        code, said = _tell(_suspicious(*[_finding(f"node_modules/p{n}/package.json") for n in range(7)]))
        self.assertEqual(said.count(what_it_is(*_GHOST)), 5)
        self.assertIn(left_out_line(2), said)

    def test_confirmed_findings_are_named_first(self):
        late = _finding("node_modules/late/package.json", confidence="confirmed")
        said = _tell(_suspicious(*[_finding(f"node_modules/p{n}/package.json") for n in range(6)], late))[1]
        self.assertIn("node_modules/late/package.json", said)
        self.assertIn(left_out_line(2), said)


if __name__ == "__main__":
    unittest.main()
