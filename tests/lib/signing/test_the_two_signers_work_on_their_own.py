#!/usr/bin/env python3
"""The commit signer and the App token signer each load and work without the other."""
from __future__ import annotations

import ast
import os
import pathlib
import subprocess
import sys
import unittest

_SRC = pathlib.Path(__file__).resolve().parents[3] / "src"
_SIGNING = _SRC / "stayawake" / "lib" / "signing"


def _imports(pyfile: pathlib.Path) -> set[str]:
    """Name every module `pyfile` imports, at module level or inside a function."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(pyfile.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


def _loaded_after(statement: str) -> set[str]:
    """Run `statement` in a fresh interpreter. Returns the stayawake modules it loaded."""
    probe = f"import sys\n{statement}\nprint('\\n'.join(m for m in sys.modules if m.startswith('stayawake')))"
    env = {**os.environ, "PYTHONPATH": str(_SRC)}
    res = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env,
                         timeout=60)
    if res.returncode != 0:
        raise AssertionError(f"{statement!r} failed on its own:\n{res.stderr}")
    return set(res.stdout.split())


class TestTheTwoSignersWorkOnTheirOwn(unittest.TestCase):
    def test_the_commit_signer_never_imports_the_app_token_signer(self):
        for py in (_SIGNING / "commits").rglob("*.py"):
            with self.subTest(file=py.name):
                self.assertFalse({m for m in _imports(py) if m.startswith("stayawake.lib.signing.jwt")})

    def test_the_app_token_signer_needs_nothing_else_from_saw(self):
        self.assertFalse({m for m in _imports(_SIGNING / "jwt.py") if m.startswith("stayawake")})

    def test_the_package_imports_neither_part(self):
        self.assertFalse({m for m in _imports(_SIGNING / "__init__.py") if m.startswith("stayawake")})

    def test_the_commit_signer_loads_on_its_own_without_the_app_token_signer(self):
        loaded = _loaded_after("import stayawake.lib.signing.commits")
        self.assertNotIn("stayawake.lib.signing.jwt", loaded)

    def test_the_app_token_signer_loads_on_its_own_without_the_commit_signer(self):
        loaded = _loaded_after("import stayawake.lib.signing.jwt")
        self.assertFalse({m for m in loaded if m.startswith("stayawake.lib.signing.commits")})

    def test_git_loads_on_its_own(self):
        self.assertIn("stayawake.lib.git.write.commit", _loaded_after("import stayawake.lib.git"))

    def test_the_commit_signer_and_git_load_in_either_order(self):
        for first, second in (("stayawake.lib.signing.commits", "stayawake.lib.git"),
                              ("stayawake.lib.git", "stayawake.lib.signing.commits")):
            with self.subTest(first=first):
                _loaded_after(f"import {first}\nimport {second}")


if __name__ == "__main__":
    unittest.main()
