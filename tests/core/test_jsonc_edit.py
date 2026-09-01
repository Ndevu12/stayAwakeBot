#!/usr/bin/env python3
"""Changing one value in a settings file the person running this owns.

The bar is not "the JSON still parses". It is that everything they wrote is still there — their
comments, their spacing, the trailing comma their editor put in — because a tool that corrects one
setting and silently reformats the file has taken more than it was asked for.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security.harden import jsonc


_WITH_COMMENTS = '''{
  // the editor put this here
  "task.allowAutomaticTasks": "on",
  /* and this */
  "editor.fontSize": 13,
}
'''


class TestOnlyTheValueMoves(unittest.TestCase):
    def test_a_string_value_is_replaced_and_nothing_else_is(self):
        out, edit = jsonc.set_value(_WITH_COMMENTS, "task.allowAutomaticTasks", '"off"')

        self.assertEqual(out, _WITH_COMMENTS.replace('"on"', '"off"'))
        self.assertEqual((edit.key, edit.value, edit.was),
                         ("task.allowAutomaticTasks", '"off"', '"on"'))
        self.assertFalse(edit.adds)

    def test_comments_spacing_and_a_trailing_comma_all_survive(self):
        out, _edit = jsonc.set_value(_WITH_COMMENTS, "task.allowAutomaticTasks", '"off"')
        self.assertIn("// the editor put this here", out)
        self.assertIn("/* and this */", out)
        self.assertIn('"editor.fontSize": 13,', out)
        self.assertTrue(out.endswith("}\n"))

    def test_a_boolean_is_replaced(self):
        out, edit = jsonc.set_value('{"security.workspace.trust.enabled": false}',
                                    "security.workspace.trust.enabled", "true")
        self.assertEqual(out, '{"security.workspace.trust.enabled": true}')
        self.assertEqual(edit.was, "false")


class TestAddingAKeyThatIsNotThere(unittest.TestCase):
    def test_it_is_appended_with_the_indentation_already_in_use(self):
        out, edit = jsonc.set_value('{\n    "editor.fontSize": 13\n}\n',
                                    "task.allowAutomaticTasks", '"off"')
        self.assertIn('    "task.allowAutomaticTasks": "off"', out)
        self.assertIn('"editor.fontSize": 13,', out, "the member before it gains its separator")
        self.assertTrue(edit.adds)

    def test_an_existing_trailing_comma_is_not_doubled(self):
        out, _edit = jsonc.set_value('{\n  "a": 1,\n}\n', "b", "2")
        self.assertNotIn(",,", out)
        self.assertIn('"b": 2', out)

    def test_an_empty_object_gets_the_first_member(self):
        out, edit = jsonc.set_value("{}\n", "b", "2")
        self.assertEqual(out, '{\n  "b": 2\n}\n')
        self.assertTrue(edit.adds)

    def test_a_file_that_is_not_one_object_is_refused(self):
        self.assertIsNone(jsonc.set_value("[1, 2]\n", "b", "2"))
        self.assertIsNone(jsonc.set_value("// only a comment\n", "b", "2"))


class TestItRefusesRatherThanGuess(unittest.TestCase):
    def test_a_key_that_appears_twice_is_not_edited(self):
        """Nested inside another object, or duplicated — neither is a place to guess which one
        the reader meant."""
        text = '{\n  "a.b": "on",\n  "other": { "a.b": "on" }\n}\n'
        self.assertIsNone(jsonc.set_value(text, "a.b", '"off"'))

    def test_a_value_that_is_already_correct_is_refused(self):
        """So a caller cannot read "nothing changed" as "changed". Ask `value_at` first."""
        self.assertIsNone(jsonc.set_value('{"a": "off"}', "a", '"off"'))
        self.assertEqual(jsonc.value_at('{"a": "off"}', "a"), '"off"')

    def test_a_structure_is_not_a_value_it_will_speak_about(self):
        self.assertIsNone(jsonc.value_at('{"a": {"b": 1}}', "a"))
        self.assertIsNone(jsonc.value_at('{"a": [1]}', "a"))

    def test_an_absent_key_has_no_value(self):
        self.assertIsNone(jsonc.value_at('{"a": 1}', "zzz"))


class TestOneEntryInsideATable(unittest.TestCase):
    TABLE = '''{
  "chat.tools.terminal.autoApprove": {
    "npx": true,
    "git status": true,
    "nested": { "npx": true }
  }
}
'''

    def test_an_entry_is_flipped_where_it_sits(self):
        out, edit = jsonc.set_member(self.TABLE, "chat.tools.terminal.autoApprove", "git status",
                                     "false")
        self.assertIn('"git status": false', out)
        self.assertIn('"npx": true', out, "nothing else in the table moves")
        self.assertEqual(edit.key, "chat.tools.terminal.autoApprove.git status")
        self.assertEqual(edit.was, "true")

    def test_an_entry_appearing_twice_in_the_table_is_refused(self):
        self.assertIsNone(jsonc.set_member(self.TABLE, "chat.tools.terminal.autoApprove", "npx",
                                           "false"))

    def test_an_entry_that_is_not_there_is_never_added(self):
        """Adding one would invent an entry they never had."""
        self.assertIsNone(jsonc.set_member(self.TABLE, "chat.tools.terminal.autoApprove", "curl",
                                           "false"))

    def test_a_table_that_is_not_there_is_refused(self):
        self.assertIsNone(jsonc.set_member('{"a": 1}', "chat.tools.terminal.autoApprove", "npx",
                                           "false"))


if __name__ == "__main__":
    unittest.main()
