#!/usr/bin/env python3
"""A delete somewhere else in the file is not the delete that walk found.

The home-walk arm required the traversal to be rooted at `$HOME` but searched the WHOLE file for a
delete, so mere co-presence satisfied it — a volume-shaped test wearing a scope-shaped label. A
dotfile manager that lists `$HOME` in one function and unlinks a temp file in another graded
INFECTED, and on a real editor bundle the "walk" was a shell snippet in documentation while the
"delete" was the word `-delete-char` in help text, 336,053 characters away.

Bringing the delete inside the walk's own statement window does NOT work — walk-then-delete is two
statements by definition — so the test is whether the walk's SCOPE is still open where the delete is.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security.taint.destructive import detect_destructive


class TestCoPresenceIsNotScope(unittest.TestCase):
    def _fires(self, source):
        return detect_destructive(source) is not None

    def test_a_dotfile_manager_is_clean(self):
        self.assertFalse(self._fires(
            'const fs = require("fs"), os = require("os");\n'
            'function listHome()    { return fs.readdirSync(os.homedir()); }\n'
            'function cleanupTemp(t){ fs.unlinkSync(t); }\n'))

    def test_the_python_shape_of_the_same_thing_is_clean(self):
        self.assertFalse(self._fires(
            "import os\n"
            "def list_home(): return os.listdir(os.path.expanduser('~'))\n"
            "def cleanup(t): os.unlink(t)\n"))

    def test_a_delete_in_a_later_class_method_is_clean(self):
        self.assertFalse(self._fires(
            'function listHome(){ return fs.readdirSync(os.homedir()); }\n'
            'class T { clear(p){ fs.unlinkSync(p); } }\n'))

    def test_a_delete_far_away_in_unrelated_text_is_clean(self):
        # The shape measured in a real editor bundle: a documented shell command and the word
        # "-delete-char" in help text, 336,053 characters apart. Scope alone does not reject that in
        # a flat file, so distance does — bounded at 4,000 against a largest-measured positive of
        # 1,692 (a loop with a 120-line body).
        self.assertFalse(self._fires(
            'const help = "find ~/.brew-aliases/ -type f";\n'
            + "// filler\n" * 3000
            + 'const key = "-delete-char deletes one character";\n'))

    def test_a_loop_with_a_long_body_still_fires(self):
        # The bound must not cut a real positive: this is the largest shape measured, x1.
        self.assertTrue(self._fires(
            "for root, dirs, files in os.walk(os.path.expanduser('~')):\n"
            + "    log(root)\n" * 120
            + "    os.unlink(root)\n"))


class TestTheCanonicalLoopsStillFire(unittest.TestCase):
    def _fires(self, source):
        return detect_destructive(source) is not None

    def test_the_javascript_loop(self):
        self.assertTrue(self._fires(
            'const files = fs.readdirSync(os.homedir());\n'
            'for (const f of files) { fs.rmSync(f, {recursive:true, force:true}); }\n'))

    def test_the_python_loop(self):
        self.assertTrue(self._fires(
            "for root, dirs, files in os.walk(os.path.expanduser('~')):\n"
            "    for f in files:\n"
            "        os.unlink(os.path.join(root, f))\n"))

    def test_a_delete_nested_in_the_walk_callback(self):
        self.assertTrue(self._fires(
            "fs.readdirSync(os.homedir()).forEach(f => {\n  fs.rmSync(f, {recursive:true});\n});\n"))

    def test_listdir_is_a_home_walk_too(self):
        # Found while fixing the above: the most idiomatic Python home walk was not a walk verb.
        self.assertTrue(self._fires(
            "def wipe():\n"
            "    for f in os.listdir(os.path.expanduser('~')):\n"
            "        os.unlink(f)\n"))


class TestHomeBoundToANameIsStillHome(unittest.TestCase):
    """One assignment used to defeat the arm entirely — the shortest possible evasion."""

    def _fires(self, source):
        return detect_destructive(source) is not None

    def test_a_name_bound_to_home_is_deleted_recursively(self):
        for name, source in {
            "js rmSync": "const h = os.homedir();\nfs.rmSync(h, { recursive: true, force: true });\n",
            "py rmtree": "home = os.path.expanduser('~')\nshutil.rmtree(home)\n",
        }.items():
            with self.subTest(shape=name):
                self.assertTrue(self._fires(source))

    def test_a_name_rebound_to_somewhere_else_is_not_home(self):
        self.assertFalse(self._fires(
            "let h = os.homedir();\nh = os.tmpdir();\nfs.rmSync(h, {recursive:true});\n"))

    def test_a_generic_name_reused_across_a_library_is_not_home(self):
        # Measured on pip's vendored distlib: `result = os.path.expanduser('~')` early in a large
        # file, `result` reused for a dozen unrelated values, an unrelated rmtree much later.
        self.assertFalse(self._fires(
            "result = os.path.expanduser('~')\n"
            + "result = compute(x)\n" * 20
            + "shutil.rmtree(result)\n"))

    def test_a_build_directory_is_not_home(self):
        self.assertFalse(self._fires(
            'const dist = path.join(__dirname, "dist");\nfs.rmSync(dist, {recursive:true});\n'))


if __name__ == "__main__":
    unittest.main()
