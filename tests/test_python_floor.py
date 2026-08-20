#!/usr/bin/env python3
"""Nothing may use syntax newer than the Python floor in pyproject.

A multi-line expression inside an f-string is PEP 701, so it parses from 3.12 and is a SyntaxError
on 3.11 — which the package still supports. It reached CI because the machine it was written on runs
3.14, and a SyntaxError in a renderer takes out every module that imports it: one line failed 40
test modules at IMPORT, so the report said "tests failing" rather than "syntax error".

`ast.parse(feature_version=(3, 11))` does NOT reject PEP 701, so this walks for it directly.
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _floor() -> tuple[int, int]:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'requires-python\s*=\s*">=\s*(\d+)\.(\d+)"', text)
    assert match, "requires-python not found — the floor is what this test is about"
    return int(match.group(1)), int(match.group(2))


def _sources():
    for base in ("src", "tests"):
        yield from sorted((_ROOT / base).rglob("*.py"))


class TestNoSyntaxNewerThanTheFloor(unittest.TestCase):
    def test_no_multiline_expression_inside_an_f_string(self):
        if _floor() >= (3, 12):
            self.skipTest("floor is 3.12+, where PEP 701 is available")
        if sys.version_info < (3, 12):
            # Per-expression positions inside an f-string are only exact from 3.12; on 3.11 they
            # span the whole literal, so implicit concatenation reads as a violation. No loss —
            # on 3.11 the interpreter rejects the real thing outright.
            self.skipTest("f-string positions are imprecise before 3.12")
        offenders = []
        for path in _sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.JoinedStr):
                    continue
                for value in node.values:
                    if (isinstance(value, ast.FormattedValue)
                            and getattr(value, "end_lineno", value.lineno) != value.lineno):
                        offenders.append(f"{path.relative_to(_ROOT)}:{value.lineno}")
        self.assertEqual([], offenders,
                         "f-string expression spans lines (PEP 701, 3.12+): hoist it to a variable")

    def test_the_floor_is_what_ci_actually_runs(self):
        # Guards the guard: if the floor moves and the matrix does not, this test silently stops
        # covering the version that breaks.
        workflow = (_ROOT / ".github/workflows/ci.yml")
        major, minor = _floor()
        matrix = workflow.read_text(encoding="utf-8")
        self.assertTrue(f"'{major}.{minor}'" in matrix or f'"{major}.{minor}"' in matrix,
                        "the Python floor is not in the CI matrix, so nothing tests it")


if __name__ == "__main__":
    sys.exit(unittest.main())
