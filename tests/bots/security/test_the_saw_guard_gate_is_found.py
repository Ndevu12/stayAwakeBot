#!/usr/bin/env python3
"""A workflow that uses the SAW Guard action is a gated repository, and a gate saw writes uses it."""
from __future__ import annotations

import unittest

from stayawake.bots.security import guard
from stayawake.bots.security.guard.constants import SAW_GUARD_ACTION
from stayawake.bots.security.guard.detect import find_saw_guard

SHA = "93fe465d7b0266c6010778999b73b591ae082f3e"


def _workflow(uses: str) -> dict[str, str]:
    return {".github/workflows/worm-guard.yml":
            "on: [pull_request]\njobs:\n  saw-guard:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: {uses}\n"}


class TestTheGateIsFound(unittest.TestCase):
    def test_the_action_is_a_gate(self):
        ref = find_saw_guard(_workflow(f"{SAW_GUARD_ACTION}@{SHA}  # v0.1.4"))
        self.assertIsNotNone(ref)
        self.assertEqual(ref.ref, SHA)

    def test_the_action_is_read_in_any_case(self):
        self.assertIsNotNone(find_saw_guard(_workflow(f"{SAW_GUARD_ACTION.lower()}@{SHA}")))

    def test_another_owner_or_a_longer_name_is_not_the_gate(self):
        for uses in (f"someone/SAW_GUARD@{SHA}", f"{SAW_GUARD_ACTION}_fork@{SHA}",
                     f"{SAW_GUARD_ACTION}-mirror@{SHA}"):
            self.assertIsNone(find_saw_guard(_workflow(uses)), uses)


class TestAGateSawWritesUsesTheAction(unittest.TestCase):
    def test_a_new_gate_workflow_pins_the_action(self):
        text = guard.render_workflow(guard.Pin(SHA, "v0.1.4"), "main", "0.12.1")
        self.assertIn(f"{SAW_GUARD_ACTION}@{SHA}", text)


if __name__ == "__main__":
    unittest.main()
