#!/usr/bin/env python3
"""Where a package manager puts what it installs — one answer for every caller.

A reader that grades installed code and a remover that clears it must agree. These hold the
layouts the ecosystem actually produces, so neither can be taught one the other does not know.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import layout


def _pkg(at: Path, name: str, version: str = "1.0.0") -> Path:
    at.mkdir(parents=True, exist_ok=True)
    (at / "package.json").write_text(json.dumps({"name": name, "version": version}),
                                     encoding="utf-8")
    return at


def _names(root: Path) -> list[str]:
    found = []
    for tree in layout.installed_trees(root):
        for directory in layout.package_dirs(tree):
            try:
                found.append(json.loads((directory / "package.json").read_text())["name"])
            except (OSError, ValueError, KeyError):
                continue
    return sorted(set(found))


class TestEveryLayoutTheEcosystemProduces(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()) / "app"
        self.nm = self.root / layout.INSTALLED_DIR
        self.nm.mkdir(parents=True)

    def test_packages_laid_out_flat(self):
        _pkg(self.nm / "left-pad", "left-pad")
        self.assertEqual(_names(self.root), ["left-pad"])

    def test_a_package_under_a_scope(self):
        _pkg(self.nm / "@scope" / "thing", "@scope/thing")
        self.assertEqual(_names(self.root), ["@scope/thing"])

    def test_a_package_nested_inside_another(self):
        _pkg(self.nm / "outer", "outer")
        _pkg(self.nm / "outer" / layout.INSTALLED_DIR / "inner", "inner")
        self.assertEqual(_names(self.root), ["inner", "outer"])

    def test_a_store_the_top_level_only_links_to(self):
        # The layout of every isolated installer: real packages in a dot-directory keyed by
        # name@version, and the top level a link into it.
        for store in (".pnpm", ".bun", ".deno", ".store"):
            with self.subTest(store=store):
                root = Path(tempfile.mkdtemp()) / "app"
                nm = root / layout.INSTALLED_DIR
                nm.mkdir(parents=True)
                real = _pkg(nm / store / "left-pad@1.0.0" / layout.INSTALLED_DIR / "left-pad",
                            "left-pad")
                (nm / "left-pad").symlink_to(real)
                self.assertEqual(_names(root), ["left-pad"], f"{store} store was not read")

    def test_a_scoped_package_held_in_a_store(self):
        real = _pkg(self.nm / ".pnpm" / "@scope+thing@1.0.0" / layout.INSTALLED_DIR / "@scope"
                    / "thing", "@scope/thing")
        (self.nm / "@scope").mkdir()
        (self.nm / "@scope" / "thing").symlink_to(real)
        self.assertEqual(_names(self.root), ["@scope/thing"])

    def test_a_tree_belonging_to_a_workspace(self):
        _pkg(self.nm / "left-pad", "left-pad")
        _pkg(self.root / "packages" / "app" / layout.INSTALLED_DIR / "evil-dep", "evil-dep")
        self.assertEqual(_names(self.root), ["evil-dep", "left-pad"])

    def test_a_tree_nobody_declared(self):
        _pkg(self.root / "tools" / "scripts" / layout.INSTALLED_DIR / "buried", "buried")
        self.assertEqual(_names(self.root), ["buried"])

    def test_a_package_is_read_once_however_many_names_reach_it(self):
        real = _pkg(self.nm / ".pnpm" / "left-pad@1.0.0" / layout.INSTALLED_DIR / "left-pad",
                    "left-pad")
        for alias in ("left-pad", "also-left-pad"):
            (self.nm / alias).symlink_to(real)
        trees = layout.installed_trees(self.root)
        directories = [d for tree in trees for d in layout.package_dirs(tree)]
        self.assertEqual(len(directories), len(set(directories)))


class TestItDoesNotWanderOffTheTree(unittest.TestCase):
    def test_a_link_out_of_the_repository_is_not_followed(self):
        root = Path(tempfile.mkdtemp()) / "app"
        nm = root / layout.INSTALLED_DIR
        nm.mkdir(parents=True)
        outside = Path(tempfile.mkdtemp()) / "elsewhere"
        _pkg(outside, "linked")
        (nm / "linked").symlink_to(outside)
        self.assertEqual(_names(root), [])

    def test_the_git_directory_is_never_walked(self):
        root = Path(tempfile.mkdtemp()) / "app"
        (root / ".git" / layout.INSTALLED_DIR).mkdir(parents=True)
        self.assertEqual(layout.installed_trees(root), [])

    def test_a_directory_it_cannot_read_is_recorded(self):
        import os
        if os.geteuid() == 0:
            self.skipTest("root reads a directory whatever its mode says")
        root = Path(tempfile.mkdtemp()) / "app"
        locked = root / "locked"
        locked.mkdir(parents=True)
        locked.chmod(0o000)
        unreadable: list[Path] = []
        try:
            layout.installed_trees(root, unreadable)
        finally:
            locked.chmod(0o755)
        self.assertEqual(unreadable, [locked])

    def test_a_tree_deeper_than_the_bound_stops(self):
        root = Path(tempfile.mkdtemp()) / "app"
        here = root / layout.INSTALLED_DIR
        for depth in range(layout._MAX_DEPTH + 3):
            here = _pkg(here / f"p{depth}", f"p{depth}") / layout.INSTALLED_DIR
        found = list(layout.package_dirs(root / layout.INSTALLED_DIR))
        self.assertLessEqual(len(found), layout._MAX_DEPTH + 1)


class TestItNeverTakesAControlThisToolPlaced(unittest.TestCase):
    """`saw harden` denies a location by holding an empty directory there. A removal must not
    collect one: the tool would take its own control off the machine it just hardened."""

    def test_no_denied_location_is_collected_as_an_installed_tree(self):
        from stayawake.bots.security.hygiene.host_artifacts import _global_folders
        root = Path(tempfile.mkdtemp()) / "home"
        root.mkdir(parents=True)
        for denial in _global_folders():
            try:
                relative = denial.relative_to(Path.home())
            except ValueError:
                continue                                  # a prefix path, never inside a repository
            (root / relative).mkdir(parents=True, exist_ok=True)
        _pkg(root / "proj" / layout.INSTALLED_DIR / "left-pad", "left-pad")
        trees = layout.installed_trees(root)
        self.assertEqual([str(t.relative_to(root)) for t in trees],
                         [str(Path("proj") / layout.INSTALLED_DIR)])


if __name__ == "__main__":
    unittest.main()
