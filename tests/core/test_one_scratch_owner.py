#!/usr/bin/env python3
"""`utils.scratch` is the only thing that makes scratch.

A temp created with no `dir=` lands in the system temp directory: that is scratch, it outlives the
run unless something removes it, and it belongs to the one owner. A temp created with `dir=` sits
beside the file it will replace — that is an atomic write, which must stay on the destination's
filesystem, and is not scratch.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "stayawake"
OWNER = SRC / "utils" / "scratch.py"

# Every tempfile entry point that CREATES something.
MAKERS = frozenset({"mkdtemp", "mkstemp", "mktemp", "TemporaryDirectory", "NamedTemporaryFile",
                    "TemporaryFile", "SpooledTemporaryFile"})


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        if path == OWNER:
            continue
        yield path, ast.parse(path.read_text(encoding="utf-8"))


def _where(path: Path, node: ast.AST) -> str:
    return f"{path.relative_to(SRC.parent.parent)}:{node.lineno}"


class TestNothingMakesItsOwnScratch(unittest.TestCase):
    def test_no_module_creates_a_temp_outside_the_owner(self):
        offenders = []
        for path, tree in _modules():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                name = (fn.attr if isinstance(fn, ast.Attribute)
                        else fn.id if isinstance(fn, ast.Name) else None)
                if name not in MAKERS:
                    continue
                if isinstance(fn, ast.Attribute) and not (
                        isinstance(fn.value, ast.Name) and fn.value.id == "tempfile"):
                    continue
                if any(kw.arg == "dir" for kw in node.keywords):
                    continue
                offenders.append(f"{_where(path, node)}: tempfile.{name}(…)")
        self.assertEqual([], offenders,
                         "use stayawake.utils.scratch instead of making scratch directly:\n  "
                         + "\n  ".join(offenders))

    def test_no_module_imports_a_temp_maker_by_name(self):
        offenders = []
        for path, tree in _modules():
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "tempfile":
                    for alias in node.names:
                        if alias.name in MAKERS:
                            offenders.append(f"{_where(path, node)}: from tempfile import {alias.name}")
        self.assertEqual([], offenders,
                         "import stayawake.utils.scratch instead:\n  " + "\n  ".join(offenders))

    def test_the_owner_is_the_one_that_makes_them(self):
        made = {n.func.attr for n in ast.walk(ast.parse(OWNER.read_text(encoding="utf-8")))
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in MAKERS}
        self.assertTrue(made, "the owner no longer makes any temp — this rule has lost its subject")


if __name__ == "__main__":
    unittest.main()
