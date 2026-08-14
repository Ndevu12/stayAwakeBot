#!/usr/bin/env python3
"""The audit report must not carry attacker-chosen control sequences to the terminal or to CI.

Filenames reach `HygieneIssue.detail` from world-writable directories — `/tmp` is `0o1777`, so any
local user, or the payload itself, chooses them. The scan renderer already routes untrusted text
through `textsafe`; the audit renderer did not, so the two surfaces had different trust postures for
the same class of input.

An escape sequence has zero display width, so it corrupts the wrapper's arithmetic AND executes on the
terminal — an erase-line run scrubs the findings above it, which is a finding-suppression primitive
handed to exactly the population this report describes.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security import hygiene
from stayawake.bots.security.hygiene.models import HygieneIssue

HOSTILE = ("Found: /tmp/mac$user\x1b]0;pwned\x07::error::FAKE-saw-says-clean\x1b[2J"
           "##[error]also-this‮gnitcefni‬")


def _rendered(**kw):
    issue = HygieneIssue(id="host-artifact", severity="warning",
                         title=kw.get("title", "t"), detail=kw.get("detail", "d"),
                         remediation=kw.get("remediation", "r"), command=kw.get("command"))
    out = hygiene.render([issue], color=False)
    return out if isinstance(out, str) else "\n".join(out)


class TestAttackerChosenTextIsDefanged(unittest.TestCase):
    def test_control_sequences_never_reach_the_report(self):
        for field in ("title", "detail", "remediation"):
            with self.subTest(field=field):
                out = _rendered(**{field: HOSTILE})
                self.assertNotIn("\x1b", out, f"escape survived via {field}")
                self.assertNotIn("‮", out, f"bidi override survived via {field}")

    def test_ci_command_introducers_are_defanged(self):
        # `::error::` is parsed at line start; the legacy `##[cmd]` form is matched ANYWHERE in a line
        # by actions/runner, so both must be neutralised, not merely moved off column zero.
        for field in ("title", "detail", "remediation"):
            with self.subTest(field=field):
                out = _rendered(**{field: HOSTILE})
                self.assertNotIn("::error::", out)
                self.assertNotIn("##[", out)

    def test_the_finding_still_renders(self):
        # Defanging must not silence the report — an encoder that drops the line is worse than the bug.
        out = _rendered(detail=HOSTILE)
        self.assertTrue(out.strip())
        self.assertIn("mac", out)

    def test_the_copy_pasteable_command_stays_verbatim(self):
        # `command` renders verbatim by design (saw#86) and is built from our own literals; encoding it
        # would corrupt a command the operator is meant to paste.
        out = _rendered(command="rm -f ~/.npmrc && echo 'done'")
        self.assertIn("rm -f ~/.npmrc && echo 'done'", out)


if __name__ == "__main__":
    unittest.main()
