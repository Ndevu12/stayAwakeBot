#!/usr/bin/env python3
"""Cursor's copies of the agent briefing stay byte-identical to Claude's.

`.cursor/skills/` is the Cursor mirror of `.claude/skills/`; `AGENTS.md` is the
Cursor mirror of `CLAUDE.md`. A change to one that does not update the other is
a drift, not a Cursor-specific edit.
"""
from __future__ import annotations

import pathlib
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _files(root: pathlib.Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


class TestAgentSkillsLockstep(unittest.TestCase):
    def test_cursor_skills_match_claude_skills(self):
        self.assertEqual(_files(_ROOT / ".claude" / "skills"),
                         _files(_ROOT / ".cursor" / "skills"))

    def test_agents_md_matches_claude_md(self):
        self.assertEqual((_ROOT / "AGENTS.md").read_text(encoding="utf-8"),
                         (_ROOT / "CLAUDE.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
