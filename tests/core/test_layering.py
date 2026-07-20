#!/usr/bin/env python3
"""Layering guard: nothing under `core/` may import UP into a bot (#1236).

`core/` is the shared lower layer (utilities + adapters); `bots/` is the application layer above it.
A `core` module that imports `stayawake.bots.*` is a dependency inversion — it drags domain policy
down into the shared layer and couples every `core` consumer to that bot. This test walks the WHOLE
AST (so it catches lazy imports inside functions too, not just module-level ones) and would have
caught the `core/git/merge/corroborate.py` → `bots.security.obfuscation` inversion this fixed.
"""
from __future__ import annotations

import ast
import pathlib
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORE = _REPO_ROOT / "src" / "stayawake" / "core"


def _bots_imports(pyfile: pathlib.Path) -> list[str]:
    tree = ast.parse(pyfile.read_text(encoding="utf-8"), filename=str(pyfile))
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("stayawake.bots"):
            hits.append(node.module)
        elif isinstance(node, ast.Import):
            hits += [a.name for a in node.names if a.name.startswith("stayawake.bots")]
    return hits


class TestCoreDoesNotImportBots(unittest.TestCase):
    def test_no_core_module_imports_up_into_a_bot(self):
        offenders = {}
        for py in _CORE.rglob("*.py"):
            if "__pycache__" in py.parts:
                continue
            hits = _bots_imports(py)
            if hits:
                offenders[str(py.relative_to(_REPO_ROOT))] = hits
        self.assertEqual(
            offenders, {},
            "core/ must not import stayawake.bots.* — a lower layer depending up on the security "
            f"domain is a dependency inversion (#1236). Offenders: {offenders}")


if __name__ == "__main__":
    unittest.main()
