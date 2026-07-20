#!/usr/bin/env python3
"""Layering guard: a package may import only from STRICTLY-LOWER layers, never sideways-up (#1236).

The shared foundation is layered bottom-to-top:

    utils/  →  core/  →  bots/  →  cli/

(`lib/` slots in between `utils` and `core` once the integration modules move there.) A module in a
layer must not import from any HIGHER layer — that would be a dependency inversion (e.g. the old
`core/git/merge/corroborate.py` importing `bots.security.obfuscation`, fixed in #1245). This walks
the FULL AST of every module, so lazy imports inside functions count too.
"""
from __future__ import annotations

import ast
import pathlib
import unittest

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "stayawake"

# Low → high. A package may import only from packages to its LEFT.
_LAYERS = ["utils", "lib", "core", "bots", "cli"]


def _imported_top_packages(pyfile: pathlib.Path) -> set[str]:
    """The `stayawake.<pkg>` top-level packages this file imports (module-level AND lazy)."""
    tree = ast.parse(pyfile.read_text(encoding="utf-8"), filename=str(pyfile))
    pkgs: set[str] = set()
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
        elif isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        for n in names:
            parts = n.split(".")
            if len(parts) >= 2 and parts[0] == "stayawake":
                pkgs.add(parts[1])
    return pkgs


class TestLayering(unittest.TestCase):
    def test_no_module_imports_a_higher_layer(self):
        offenders = {}
        for i, layer in enumerate(_LAYERS):
            higher = set(_LAYERS[i + 1:])
            root = _SRC / layer
            if not root.exists():
                continue
            for py in root.rglob("*.py"):
                if "__pycache__" in py.parts:
                    continue
                bad = _imported_top_packages(py) & higher
                if bad:
                    offenders[str(py.relative_to(_SRC.parent.parent))] = sorted(bad)
        self.assertEqual(
            offenders, {},
            "a layer may import only strictly-lower layers (low→high: "
            f"{' → '.join(_LAYERS)}); upward imports are a dependency inversion (#1236): {offenders}")


if __name__ == "__main__":
    unittest.main()
