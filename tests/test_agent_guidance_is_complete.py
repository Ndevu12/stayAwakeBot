#!/usr/bin/env python3
"""The agent guidance is one source of truth, and every security rule survives.

The canonical `AGENTS.md` carries the full governed-git contract. Per-vendor adapters only *point*
at it — they must never become partial copies, because a dropped rule (for example "do not bypass")
is a security hole. This pins both: the canonical keeps every rule, and each adapter references it.
"""
from __future__ import annotations

import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GUIDE = _ROOT / "agent-guidance" / "governed-git"
_CANONICAL = _GUIDE / "AGENTS.md"

# The rules that must never silently disappear from the canonical. Phrases, not whole sentences,
# so wording can improve without the guard going stale — but the rule itself must be present.
_REQUIRED = [
    "Do not run a raw bringing-files command",
    "Wait for the verdict",
    "Act only on a clean",
    "Tell the operator",
    "Never disable, skip, or work around",
    "held means held",
    "could not finish is",            # a check that could not finish is never clean
    "Honest limit",                   # the honest ceiling must stay stated
    "cannot",                         # ...it cannot make it impossible to bypass
    "clean", "residue", "suspicious", "could not scan", "infected",  # every verdict
]

_ADAPTERS = ["adapters/cursor.mdc", "adapters/copilot-instructions.md", "adapters/claude-SKILL.md"]


class TestCanonicalKeepsEveryRule(unittest.TestCase):
    def test_the_canonical_exists_and_carries_every_rule(self):
        self.assertTrue(_CANONICAL.is_file(), f"missing {_CANONICAL}")
        text = _CANONICAL.read_text(encoding="utf-8")
        missing = [r for r in _REQUIRED if r.lower() not in text.lower()]
        self.assertEqual([], missing, f"the canonical dropped: {missing}")


class TestAdaptersOnlyPointAtTheCanonical(unittest.TestCase):
    def test_each_adapter_references_agents_md(self):
        for rel in _ADAPTERS:
            with self.subTest(adapter=rel):
                p = _GUIDE / rel
                self.assertTrue(p.is_file(), f"missing {p}")
                self.assertIn("agents.md", p.read_text(encoding="utf-8").lower(),
                              f"{rel} must point at AGENTS.md, not re-implement the rules")


if __name__ == "__main__":
    unittest.main()
