#!/usr/bin/env python3
"""`saw harden` turns off an auto-approved key that names a risky command in more than one word,
such as "yarn dev", exactly as the settings spell it, and leaves the other keys as they are."""
from __future__ import annotations

import json
import unittest

from stayawake.bots.security.harden import settings
from stayawake.bots.security.hygiene import editor

_SETTINGS = """{
  "chat.tools.terminal.autoApprove": {
    "npx": true, "supabase": true, "yarn lint": true, "yarn dev": true,
    "ssh": true, "sed": true, "awk": true, "uniq": true, "git add": true,
    "pnpm start": { "approve": true }, "npm test": false
  }
}
"""


def _after_harden() -> dict:
    text, planned, skipped = settings.plan(_SETTINGS, ["editor-autoapprove-risky"])
    assert not skipped, skipped
    return json.loads(text)["chat.tools.terminal.autoApprove"]


class TestAMultiWordAutoApprovalIsTurnedOff(unittest.TestCase):
    def test_yarn_dev_and_yarn_lint_are_turned_off(self):
        after = _after_harden()
        self.assertIs(after["yarn dev"], False)
        self.assertIs(after["yarn lint"], False)

    def test_the_object_form_is_turned_off(self):
        self.assertEqual({"approve": False}, _after_harden()["pnpm start"])

    def test_a_single_word_risky_key_is_still_turned_off(self):
        self.assertIs(_after_harden()["npx"], False)

    def test_keys_that_name_no_risky_command_are_left_alone(self):
        after = _after_harden()
        self.assertIs(after["uniq"], True)
        self.assertIs(after["git add"], True)
        self.assertIs(after["npm test"], False)

    def test_the_audit_still_names_the_risky_commands(self):
        self.assertIn("yarn", editor.risky_autoapprove_entries(_SETTINGS))
        self.assertIn("yarn dev", editor.risky_autoapprove_keys(_SETTINGS))


if __name__ == "__main__":
    unittest.main()
