#!/usr/bin/env python3
"""Tests for `cli.resolve.render` — safe rendering of an uncertain file for the operator prompt.

The file's bytes are attacker-controlled, so the tests drive hostile previews (escapes, bidi,
Actions log-commands, binary) and confirm each is neutralised or withheld, plus the honest
blast-radius states.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security.pr.resolve import UncertainItem
from stayawake.cli.resolve.render import render_item


def _item(**kw):
    base = dict(path="src/x.js", category="code-loader", signature_id="loader-seam",
                description="packed loader", preview=b"const a = 1;\n",
                introduced_by="", arrived_with_removed=())
    base.update(kw)
    return UncertainItem(**base)


class TestRenderItem(unittest.TestCase):
    def test_a_readable_file_is_previewed_with_a_gutter(self):
        out = render_item(_item(preview=b"line one\nline two\n"))
        self.assertIn("do NOT trust", out)
        self.assertIn("src/x.js", out)
        self.assertIn("1│ line one", out)
        self.assertIn("2│ line two", out)

    def test_terminal_escapes_are_neutralised(self):
        out = render_item(_item(preview=b"\x1b[31mred\x1b[0m\x9bx\n"))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x9b", out)

    def test_actions_log_commands_are_defanged(self):
        out = render_item(_item(preview=b"##[error]boom\n::set-output name=x::1\n"))
        self.assertNotIn("##[", out)
        self.assertNotIn("::", out)

    def test_a_bidi_override_is_stripped(self):
        out = render_item(_item(preview="safe‮evil\n".encode()))
        self.assertNotIn("‮", out)

    def test_binary_content_is_withheld(self):
        out = render_item(_item(preview=b"MZ\x00\x00binary\x00blob"))
        self.assertIn("not printing", out)
        self.assertNotIn("binary\x00blob", out)

    def test_an_opaque_category_is_judged_from_the_finding_not_bytes(self):
        out = render_item(_item(category="fake-font", preview=b"readable but a font\n"))
        self.assertIn("judge this from the finding", out)
        self.assertNotIn("readable but a font", out)

    def test_the_preview_is_capped_at_twenty_lines(self):
        out = render_item(_item(preview=("x\n" * 100).encode()))
        self.assertIn("more not shown", out)
        self.assertEqual(out.count("│"), 20)

    def test_the_blast_radius_names_what_it_arrived_with(self):
        out = render_item(_item(introduced_by="deadbeef1234",
                                arrived_with_removed=("a/loader.js", "b/postinstall.js")))
        self.assertIn("deadbeef1234", out)
        self.assertIn("a/loader.js", out)
        self.assertIn("2 files saw is already removing", out)

    def test_an_unplaceable_file_says_treat_with_caution(self):
        out = render_item(_item(introduced_by="", arrived_with_removed=()))
        self.assertIn("could not determine", out)
        self.assertIn("treat with caution", out)

    def test_a_heuristic_file_says_unsure(self):
        self.assertIn("saw is unsure", render_item(_item()))

    def test_a_confirmed_unremediable_file_says_saw_confirmed_it(self):
        out = render_item(_item(confirmed=True))
        self.assertIn("saw confirmed this file is malicious", out)
        self.assertNotIn("saw is unsure", out)


if __name__ == "__main__":
    unittest.main()
