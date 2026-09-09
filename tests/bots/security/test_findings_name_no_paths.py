#!/usr/bin/env python3
"""A finding says what to do, not where it is.

A report is read over a shoulder, pasted into a ticket and attached to a mail. Every location it
prints is a map to what is worth taking, written by the tool that went looking for it."""
from __future__ import annotations

import ast
import pathlib
import re
import unittest

_HYGIENE = pathlib.Path(__file__).resolve().parents[3] / "src/stayawake/bots/security/hygiene"

_LOCATION_NAMES = re.compile(
    r"^(p|path|paths|where|target|located|settings|file|dirs?|folder|"
    r"location|locations|script|keys_file|profile|sink|exec_path)$")

_LOOKS_LIKE_A_PATH = re.compile(r"(^|\s)(/|~/)[\w.\-/]|Found:")

_SPEAKS_TO_THE_OPERATOR = ("title", "detail", "remediation")

NOT_REWRITTEN_YET = {
    "git-credentials-plaintext",
    "ssh-dir-writable", "ssh-authorized-keys-writable", "ssh-authorized-keys-forced-command",
    "ssh-authorized-keys-restricted", "shell-profile-fetch-exec",
    "live-obfuscated-process",
}


def _issue_calls():
    """Every `HygieneIssue(...)` built under `hygiene/`, as (file, id, spoken text)."""
    for source in sorted(_HYGIENE.rglob("*.py")):
        tree = ast.parse(source.read_text())
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "HygieneIssue"):
                continue
            kw = {k.arg: k.value for k in node.keywords}
            ident = kw.get("id")
            ident = ident.value if isinstance(ident, ast.Constant) else "<computed>"
            spoken = [kw[name] for name in _SPEAKS_TO_THE_OPERATOR if name in kw]
            yield source.name, ident, spoken


def _names_a_location(nodes) -> list[str]:
    """The location-ish expressions this text would print."""
    named: list[str] = []
    for node in nodes:
        for inner in ast.walk(node):
            if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                if _LOOKS_LIKE_A_PATH.search(inner.value):
                    named.append(inner.value.strip()[:40])
            if isinstance(inner, ast.FormattedValue):
                if (isinstance(inner.value, ast.Call)
                        and getattr(inner.value.func, "id", "") == "len"):
                    continue
                for leaf in ast.walk(inner.value):
                    if isinstance(leaf, ast.Name) and _LOCATION_NAMES.match(leaf.id):
                        named.append(leaf.id)
                    if isinstance(leaf, ast.Attribute) and _LOCATION_NAMES.match(leaf.attr):
                        named.append(leaf.attr)
    return named


class TestNoFindingPrintsWhereItIs(unittest.TestCase):
    def test_no_finding_names_a_location(self):
        offending = []
        for name, ident, spoken in _issue_calls():
            if ident in NOT_REWRITTEN_YET:
                continue
            named = _names_a_location(spoken)
            if named:
                offending.append((name, ident, sorted(set(named))))
        self.assertEqual(offending, [], f"these print where they found it: {offending}")

    def test_the_list_only_shrinks(self):
        """An id that has been rewritten comes off. Nothing is ever added."""
        still_named = {ident for _f, ident, spoken in _issue_calls()
                       if _names_a_location(spoken)}
        stale = NOT_REWRITTEN_YET - still_named
        self.assertEqual(stale, set(),
                         f"rewritten — take them out of NOT_REWRITTEN_YET: {sorted(stale)}")


if __name__ == "__main__":
    unittest.main()
