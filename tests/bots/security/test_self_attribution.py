#!/usr/bin/env python3
"""What the report says about this tool's own work, and about one location versus several.

Both were reported from a real host: saw asked the operator to confirm the login item saw itself
had just installed, and the run's headline said an artifact was in more than one place when one
was found."""
from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

from stayawake.bots.security import hygiene, schedule
from stayawake.bots.security.hygiene.autorun import provenance
from stayawake.bots.security.hygiene.models import (HygieneIssue, LEFT_OUTSIDE_A_CONTROL_IDS,
                                                    TIER_LEFT_OUTSIDE_A_CONTROL,
                                                    TIER_UNCONFIRMED_STAGING,
                                                    UNCONFIRMED_STAGING_IDS, incident_tier,
                                                    response_order, rotation_safety)

SAW = ["/opt/pipx/venvs/stayawakebot/bin/python", "-E", "-P", "-m", "stayawake"]


class _OnAMachineWithSawsItem:
    """A machine holding the item saw places, on the platform under test."""

    def __init__(self, test, platform):
        self.test, self.platform = test, platform

    def __enter__(self):
        self.home = pathlib.Path(tempfile.mkdtemp())
        self.patches = [mock.patch.object(schedule.sys, "platform", self.platform),
                        mock.patch.object(pathlib.Path, "home", return_value=self.home)]
        for p in self.patches:
            p.start()
        self.item = schedule.item_path()
        self.item.parent.mkdir(parents=True, exist_ok=True)
        self.item.write_text(schedule.content(SAW), encoding="utf-8")
        self.record = self.home / "rec.json"
        schedule.declare(SAW, self.record)
        self.patches.append(mock.patch.object(schedule, "record_path", return_value=self.record))
        self.patches[-1].start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()


class TestSawDoesNotAskYouToConfirmItsOwnWork(unittest.TestCase):
    """`saw watch` places a login item; the audit then reported it as a new unattributed autorun
    entry and asked the operator to confirm they installed it. A finding an operator is trained to
    dismiss is the finding that hides the next real one."""

    def test_its_own_item_is_attributed_on_both_platforms(self):
        for platform in ("darwin", "linux"):
            with self.subTest(platform=platform), _OnAMachineWithSawsItem(self, platform) as m:
                self.assertTrue(schedule.is_ours(m.item))

    def test_the_attribution_is_the_content_not_the_name(self):
        # A name is something anyone can write. Attributing by it hands a foothold the disguise.
        for platform in ("darwin", "linux"):
            with self.subTest(platform=platform), _OnAMachineWithSawsItem(self, platform) as m:
                m.item.write_text(schedule.content(SAW) + "\nExecStartPost=/tmp/theirs\n",
                                  encoding="utf-8")
                self.assertFalse(schedule.is_ours(m.item),
                                 "an item at saw's name that saw did not write is not saw's")

    def test_the_same_bytes_somewhere_saw_never_writes_are_not_its_own(self):
        for platform in ("darwin", "linux"):
            with self.subTest(platform=platform), _OnAMachineWithSawsItem(self, platform) as m:
                copied = m.home / "elsewhere" / m.item.name
                copied.parent.mkdir(parents=True)
                copied.write_text(schedule.content(SAW), encoding="utf-8")
                self.assertFalse(schedule.is_ours(copied))

    def test_nothing_there_is_not_its_own(self):
        with _OnAMachineWithSawsItem(self, "darwin") as m:
            m.item.unlink()
            self.assertFalse(schedule.is_ours(m.item))

    def test_the_autorun_probe_asks_that_question(self):
        # The hooks already self-attribute this way; the login item is the same question.
        with _OnAMachineWithSawsItem(self, "darwin") as m:
            entry = mock.Mock(exec_path=SAW[0], path=m.item, location="launch-agent",
                              script=None)
            with mock.patch.object(provenance.hookscript, "LOCATION", "git-hooks"):
                attrib = provenance.attribute(entry)
        self.assertEqual(attrib.owner, "saw")
        self.assertTrue(attrib.attributed)

    def test_and_an_item_it_did_not_write_stays_unattributed(self):
        with _OnAMachineWithSawsItem(self, "darwin") as m:
            m.item.write_text("<plist>someone else's</plist>", encoding="utf-8")
            entry = mock.Mock(exec_path="/tmp/theirs/python", path=m.item,
                              location="launch-agent", script=None)
            with mock.patch.object(provenance.hookscript, "LOCATION", "git-hooks"):
                attrib = provenance.attribute(entry)
        self.assertNotEqual(attrib.owner, "saw")
        self.assertFalse(attrib.attributed)


def _issue(issue_id: str) -> HygieneIssue:
    return HygieneIssue(id=issue_id, severity="warning", title="t", detail="d", remediation="r")


class TestOneLocationIsNotSeveral(unittest.TestCase):
    """One path left outside a control is a different claim from the same artifact in several
    places. Both were rendered with the second one's words, so the run told an operator to compare
    locations it had never found."""

    def test_the_two_findings_are_different_tiers(self):
        self.assertEqual(UNCONFIRMED_STAGING_IDS & LEFT_OUTSIDE_A_CONTROL_IDS, set())
        self.assertEqual(incident_tier({"host-drop-artifact-outside-a-control"}),
                         TIER_LEFT_OUTSIDE_A_CONTROL)
        self.assertEqual(incident_tier({"host-drop-artifacts-staging"}), TIER_UNCONFIRMED_STAGING)

    def test_one_location_is_never_described_as_more_than_one(self):
        report = hygiene.render([_issue("host-drop-artifact-outside-a-control")], width=100)
        self.assertNotIn("more than one place", report)
        self.assertNotIn("not several", report)
        self.assertIn("left outside a control", report)

    def test_several_locations_still_say_so(self):
        report = hygiene.render([_issue("host-drop-artifacts-staging")], width=100)
        self.assertIn("more than one place", report)

    def test_the_stronger_claim_wins_when_both_are_found(self):
        report = hygiene.render([_issue("host-drop-artifact-outside-a-control"),
                                 _issue("host-drop-artifacts-staging")], width=100)
        self.assertIn("more than one place", report)

    def test_both_still_gate_credential_rotation(self):
        # Splitting the wording must not split the gate: either finding withholds the all-clear.
        for issue_id in ("host-drop-artifact-outside-a-control", "host-drop-artifacts-staging"):
            with self.subTest(issue_id=issue_id):
                self.assertNotEqual(rotation_safety({issue_id}), hygiene.ROTATION_SAFE)
                report = hygiene.render([_issue(issue_id)], width=100)
                self.assertIn("UNSAFE", report)
                self.assertIn("Do NOT rotate credentials yet", report)

    def test_the_new_tier_takes_its_place_in_the_response_order(self):
        # One table drives the banner, the ordering and the tier. A tier missing from it would sort
        # ahead of a live foothold.
        self.assertGreater(response_order("host-drop-artifact-outside-a-control"),
                           response_order("host-drop-artifacts-staging"))


if __name__ == "__main__":
    unittest.main()
