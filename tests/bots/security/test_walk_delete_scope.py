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
from tests.support import samples


class TestCoPresenceIsNotScope(unittest.TestCase):
    def _fires(self, source):
        return detect_destructive(source) is not None

    def test_a_dotfile_manager_is_clean(self):
        self.assertFalse(self._fires(
            samples.joined('const fs = require("fs"), os = require("os");\nfunction listHome()    { return fs.r', 'eaddirSync(o', 's.homedir()); }\nfunction cleanupTemp(t){ fs.u', 'nlinkSync(t); }\n')))

    def test_the_python_shape_of_the_same_thing_is_clean(self):
        self.assertFalse(self._fires(
            samples.joined('import os\ndef list_home(): return os.l', 'istdir(os.path.e', "xpanduser('~'))\ndef cleanup(t): os.u", 'nlink(t)\n')))

    def test_a_delete_in_a_later_class_method_is_clean(self):
        self.assertFalse(self._fires(
            samples.joined('function listHome(){ return fs.r', 'eaddirSync(o', 's.homedir()); }\nclass T { clear(p){ fs.u', 'nlinkSync(p); } }\n')))

    def test_a_delete_far_away_in_unrelated_text_is_clean(self):
        # The shape measured in a real editor bundle: a documented shell command and the word
        # "-delete-char" in help text, 336,053 characters apart. Scope alone does not reject that in
        # a flat file, so distance does — bounded at 4,000 against a largest-measured positive of
        # 1,692 (a loop with a 120-line body).
        self.assertFalse(self._fires(
            samples.joined('const help = "f', 'ind ~/.brew-aliases/ -type f";\n')
            + "// filler\n" * 3000
            + samples.joined('const key = "-d', 'elete-char deletes one character";\n')))

    def test_a_loop_with_a_long_body_still_fires(self):
        # The bound must not cut a real positive: this is the largest shape measured, x1.
        self.assertTrue(self._fires(
            samples.joined('for root, dirs, files in os.w', 'alk(os.path.e', "xpanduser('~')):\n")
            + "    log(root)\n" * 120
            + samples.joined('    os.u', 'nlink(root)\n')))


class TestTheCanonicalLoopsStillFire(unittest.TestCase):
    def _fires(self, source):
        return detect_destructive(source) is not None

    def test_the_javascript_loop(self):
        self.assertTrue(self._fires(
            samples.joined('const files = fs.r', 'eaddirSync(o', 's.homedir());\nfor (const f of files) { fs.r', 'mSync(f, {recursive:true, force:true}); }\n')))

    def test_the_python_loop(self):
        self.assertTrue(self._fires(
            samples.joined('for root, dirs, files in os.w', 'alk(os.path.e', "xpanduser('~')):\n    for f in files:\n        os.u", 'nlink(os.path.join(root, f))\n')))

    def test_a_delete_nested_in_the_walk_callback(self):
        self.assertTrue(self._fires(
            samples.joined('fs.r', 'eaddirSync(o', 's.homedir()).forEach(f => {\n  fs.r', 'mSync(f, {recursive:true});\n});\n')))

    def test_listdir_is_a_home_walk_too(self):
        # Found while fixing the above: the most idiomatic Python home walk was not a walk verb.
        self.assertTrue(self._fires(
            samples.joined('def wipe():\n    for f in os.l', 'istdir(os.path.e', "xpanduser('~')):\n        os.u", 'nlink(f)\n')))


class TestHomeBoundToANameIsStillHome(unittest.TestCase):
    """One assignment used to defeat the arm entirely — the shortest possible evasion."""

    def _fires(self, source):
        return detect_destructive(source) is not None

    def test_a_name_bound_to_home_is_deleted_recursively(self):
        for name, source in {
            "js rmSync": samples.joined('const h = o', 's.homedir();\nfs.r', 'mSync(h, { recursive: true, force: true });\n'),
            "py rmtree": samples.joined('home = os.path.e', "xpanduser('~')\ns", 'hutil.rmtree(home)\n'),
        }.items():
            with self.subTest(shape=name):
                self.assertTrue(self._fires(source))

    def test_a_name_rebound_to_somewhere_else_is_not_home(self):
        self.assertFalse(self._fires(
            samples.joined('let h = o', 's.homedir();\nh = os.tmpdir();\nfs.r', 'mSync(h, {recursive:true});\n')))

    def test_a_generic_name_reused_across_a_library_is_not_home(self):
        # Measured on pip's vendored distlib: `result = os.path.expanduser('~')` early in a large
        # file, `result` reused for a dozen unrelated values, an unrelated rmtree much later.
        self.assertFalse(self._fires(
            samples.joined('result = os.path.e', "xpanduser('~')\n")
            + "result = compute(x)\n" * 20
            + samples.joined('s', 'hutil.rmtree(result)\n')))

    def test_a_build_directory_is_not_home(self):
        self.assertFalse(self._fires(
            samples.joined('const dist = path.join(__dirname, "dist");\nfs.r', 'mSync(dist, {recursive:true});\n')))


class TestSplittingIntoFunctionsDoesNotEvade(unittest.TestCase):
    """A lexical scope test is defeated by putting the walk and the delete in two functions — they
    genuinely are in different scopes. What still betrays it is the WIRING: the walk's result is
    handed to the deleter. A dotfile manager owns both halves and never connects them, which is the
    difference scope alone cannot see."""

    WALKER_JS = samples.joined('function walkHome(){ return fs.r', 'eaddirSync(o', 's.homedir()); }\n')
    DELETER_JS = samples.joined('function nuke(f){ fs.r', 'mSync(f, {recursive:true, force:true}); }\n')

    def _fires(self, source):
        return detect_destructive(source) is not None

    def test_a_callback_reference_is_wiring(self):
        self.assertTrue(self._fires(self.WALKER_JS + self.DELETER_JS + "walkHome().forEach(nuke);\n"))

    def test_a_loop_over_the_walk_result_is_wiring(self):
        self.assertTrue(self._fires(
            self.WALKER_JS + self.DELETER_JS + "for (const f of walkHome()) { nuke(f); }\n"))

    def test_the_python_shape_is_wiring_too(self):
        self.assertTrue(self._fires(
            samples.joined('def walk_home():\n    return os.l', 'istdir(os.path.e', "xpanduser('~'))\ndef nuke(f):\n    s", 'hutil.rmtree(f)\nfor f in walk_home():\n    nuke(f)\n')))

    def test_owning_both_halves_without_connecting_them_is_clean(self):
        self.assertFalse(self._fires(
            self.WALKER_JS + samples.joined('function cleanupTemp(t){ fs.u', 'nlinkSync(t); }\n')))

    def test_calling_the_walker_for_something_else_is_clean(self):
        self.assertFalse(self._fires(
            self.WALKER_JS + samples.joined('function cleanupTemp(t){ fs.u', 'nlinkSync(t); }\n')
            + "console.log(walkHome().length);\n"))

    def test_a_definition_is_not_a_call_site(self):
        # The header itself matched the call pattern at first, which put the NEXT function's name
        # inside the window and made an unwired dotfile manager read as wired.
        self.assertFalse(self._fires(self.WALKER_JS + samples.joined('function nuke(f){ fs.u', 'nlinkSync(f); }\n')))


class TestTheDeleteVocabularyCoversPython(unittest.TestCase):
    def test_rmtree_is_a_delete(self):
        # The standard Python recursive delete was absent from the delete vocabulary entirely.
        self.assertTrue(detect_destructive(
            samples.joined('for f in os.l', 'istdir(os.path.e', "xpanduser('~')):\n    s", 'hutil.rmtree(f)\n')) is not None)


if __name__ == "__main__":
    unittest.main()
