#!/usr/bin/env python3
"""Ending code that is running and never touched the disk.

The measured case is not one process. A single snapshot on an infected host held 135 of them across
1577 pids — it was spawning while the operator read the output. Everything here is about that: a
one-shot pass loses, and the only thing that makes the population shrink is that a frozen process
cannot fork.
"""
from __future__ import annotations

import os
import subprocess
import time
import unittest
from unittest import mock

from stayawake.bots.security.harden import live
from stayawake.utils import procstop
from stayawake.utils.procsnap import Identity, Process


def _held(pid, ppid=1, start=1000):
    return (Process(pid=pid, argv=("node", "-e", "payload"),
                    identity=Identity(pid=pid, ppid=ppid, uid=501, start_time=start)),
            "payload", "dynamic-exec sink")


class TestItOutlastsASpawner(unittest.TestCase):
    def test_a_population_that_grows_while_it_works_is_still_finished(self):
        # Each round reveals more, the way a spawner does, and then stops because everything that
        # could spawn is frozen.
        rounds = [[_held(10), _held(11)], [_held(10), _held(11), _held(12)],
                  [_held(10), _held(11), _held(12)], []]
        calls = iter(rounds + [[]] * 4)
        out = live.end_live_code(find=lambda: next(calls),
                                 freeze=lambda who: procstop.SIGNALLED,
                                 end=lambda who: procstop.SIGNALLED,
                                 ended=lambda who: True,
                                 capture=lambda held, where: None,
                                 protected=lambda: {1})
        self.assertEqual(out.matched, 3)
        self.assertEqual(out.ended, 3)
        self.assertTrue(out.quiet)
        self.assertTrue(out.finished)

    def test_a_source_it_cannot_see_never_reads_as_finished(self):
        # Every round brings a new pid forever: something outside the set is starting them, and
        # saying "done" here would be the lie that matters most.
        counter = iter(range(100, 400))
        out = live.end_live_code(find=lambda: [_held(next(counter))],
                                 freeze=lambda who: procstop.SIGNALLED,
                                 end=lambda who: procstop.SIGNALLED,
                                 ended=lambda who: True,
                                 capture=lambda held, where: None,
                                 protected=lambda: {1}, rounds=5)
        self.assertFalse(out.quiet, "it claimed quiet while new ones kept appearing")
        self.assertFalse(out.finished)


class TestItNeverEndsWhatWouldEndTheRun(unittest.TestCase):
    def test_this_process_and_its_ancestors_are_never_touched(self):
        # The real parent, not a synthetic one: the ancestor walk used to stop at the first process
        # it could not read, and on a default macOS terminal that is a uid-0 `login` sitting between
        # the shell and the terminal application — so everything above it lost protection.
        signalled = []
        watch = [os.getpid(), os.getppid(), 1]
        live.end_live_code(find=lambda: [_held(pid) for pid in watch],
                           freeze=lambda who: signalled.append(who.pid) or procstop.SIGNALLED,
                           end=lambda who: signalled.append(who.pid) or procstop.SIGNALLED,
                           ended=lambda who: True,
                           capture=lambda held, where: None)
        self.assertEqual(signalled, [], f"it signalled something it must not: {signalled}")

    def test_every_link_of_the_real_ancestor_chain_is_protected(self):
        from stayawake.utils.procsnap import parent_map
        parents, chain, cur = parent_map(), [], os.getpid()
        while cur in parents and cur != 1 and len(chain) < 20:
            chain.append(cur)
            cur = parents[cur]
        self.assertGreater(len(chain), 1, "no ancestor chain to check")
        safe = live._protected()
        self.assertEqual([pid for pid in chain if pid not in safe], [],
                         "a link of this run's own ancestry was left unprotected")

    def test_another_users_process_is_reported_not_retried(self):
        seen = []
        def freeze(who):
            seen.append(who.pid)
            return procstop.REFUSED
        out = live.end_live_code(find=lambda: [_held(77)], freeze=freeze,
                                 end=lambda who: procstop.SIGNALLED,
                                 ended=lambda who: True,
                                 capture=lambda held, where: None,
                                 protected=lambda: {1}, rounds=6)
        self.assertEqual(out.refused, [77])
        self.assertEqual(seen, [77], "it asked again every round and got the same answer")
        self.assertFalse(out.finished)


class TestItEndsChildrenBeforeParents(unittest.TestCase):
    def test_the_order_does_not_reparent_a_child_to_init(self):
        # End the parent first and its children are reparented to init: still running, and harder
        # to attribute than they were a moment before.
        family = [_held(10, ppid=1), _held(11, ppid=10), _held(12, ppid=11)]
        order = []
        live.end_live_code(find=lambda: family if not order else [],
                           freeze=lambda who: procstop.SIGNALLED,
                           end=lambda who: order.append(who.pid) or procstop.SIGNALLED,
                           ended=lambda who: True,
                           capture=lambda held, where: None, protected=lambda: {1})
        self.assertEqual(order, [12, 11, 10])


class TestItCapturesBeforeItEnds(unittest.TestCase):
    def test_nothing_is_ended_before_the_capture_is_written(self):
        # The first stage lives only in the process. An operator who kills first has destroyed the
        # only copy — which is what happened on this project's own incident.
        events = []
        live.end_live_code(find=lambda: [_held(10)] if not events else [],
                           freeze=lambda who: procstop.SIGNALLED,
                           end=lambda who: events.append("end") or procstop.SIGNALLED,
                           ended=lambda who: True,
                           capture=lambda held, where: events.append("capture") or "/c.json",
                           protected=lambda: {1})
        self.assertEqual(events[0], "capture", f"it ended something first: {events}")

    def test_one_record_covers_the_whole_population(self):
        held = {pid: (Identity(pid=pid, ppid=1, uid=501, start_time=5), "payload")
                for pid in range(200, 335)}
        with mock.patch.object(live.Path, "mkdir"), \
             mock.patch.object(live.Path, "write_text") as written:
            out = live._capture(held, live.Path("/state"))
        self.assertEqual(written.call_count, 1, "it wrote one file per process")
        self.assertIn("live-code-", out)


class TestAgainstARealSpawner(unittest.TestCase):
    """The fakes above cannot show a race. This starts a process that really keeps forking."""

    @unittest.skipUnless(os.name == "posix", "needs POSIX signals")
    def test_a_real_forking_tree_is_ended_and_stays_ended(self):
        from stayawake.utils.procsnap import identify, snapshot
        parent = subprocess.Popen(["/bin/sh", "-c",
                                   "while :; do /bin/sleep 60 & sleep 0.05; done"])
        self.addCleanup(self._reap, parent.pid)
        time.sleep(0.8)

        def family():
            found = []
            for pid in self._descendants(parent.pid, snapshot()) | {parent.pid}:
                who, _state = identify(pid)
                if who is not None:
                    found.append((Process(pid=pid, argv=("node", "-e", "p"), identity=who),
                                  "p", "dynamic-exec sink"))
            return found

        self.assertGreater(len(family()), 1, "the spawner never started")
        out = live.end_live_code(find=family, capture=lambda held, where: None)
        self.assertTrue(out.quiet, "it never reached a quiet round")
        self.assertEqual(out.survived, [], "something outlived the pass")
        time.sleep(0.5)
        self.assertEqual(family(), [], "it came back after the pass returned")

    @staticmethod
    def _descendants(root, snap):
        by_parent = {}
        for p in snap.processes:
            if p.identity:
                by_parent.setdefault(p.identity.ppid, []).append(p.pid)
        kids, stack = set(), [root]
        while stack:
            for kid in by_parent.get(stack.pop(), []):
                if kid not in kids:
                    kids.add(kid)
                    stack.append(kid)
        return kids

    def _reap(self, pid):
        from stayawake.utils.procsnap import snapshot
        for victim in self._descendants(pid, snapshot()) | {pid}:
            try:
                os.kill(victim, 9)
            except OSError:
                pass


class TestItNeverSaysFinishedWhileSomethingHoldsIt(unittest.TestCase):
    """`finished` is the claim `harden` applies its control on. Everything here is a shape that
    used to make it True while live code was still running."""

    def test_a_holder_it_declined_to_touch_still_counts(self):
        # A protected process holding live code landed in no field at all — not matched, not
        # refused, not survived, not still_holding — and the pass reported finished.
        mine = os.getpid()
        out = live.end_live_code(find=lambda: [_held(mine)],
                                 freeze=lambda who: procstop.SIGNALLED,
                                 end=lambda who: procstop.SIGNALLED,
                                 ended=lambda who: True,
                                 capture=lambda held, where: None)
        self.assertEqual(out.still_holding, 1)
        self.assertFalse(out.finished, "a live holder it would not touch read as finished")

    def test_a_pass_that_never_went_quiet_is_not_finished(self):
        # The budget ran out with something new every round, and then the machine went silent. Every
        # other field says success — nothing survived, nothing refused, nothing holding it now — so
        # only `quiet` can carry the fact that a source it cannot see was starting them.
        counter = iter(range(500, 900))
        seen = []
        def find():
            if len(seen) >= 3:
                return []                      # still_holding reads 0: the run looks complete
            seen.append(1)
            return [_held(next(counter))]
        out = live.end_live_code(find=find, freeze=lambda who: procstop.SIGNALLED,
                                 end=lambda who: procstop.SIGNALLED, ended=lambda who: True,
                                 capture=lambda held, where: None,
                                 protected=lambda: {1}, rounds=3)
        self.assertFalse(out.quiet)
        self.assertEqual(out.survived, [])
        self.assertEqual(out.refused, [])
        self.assertEqual(out.still_holding, 0)
        self.assertFalse(out.finished, "the budget ran out and it still claimed to have finished")

    def test_an_implant_that_exited_by_itself_is_finished(self):
        # The opposite error: nothing matched because it died between one look and the next. That
        # used to read as "could not end all of it" and withheld the control.
        out = live.end_live_code(find=lambda: [], freeze=lambda who: procstop.SIGNALLED,
                                 end=lambda who: procstop.SIGNALLED, ended=lambda who: True,
                                 capture=lambda held, where: None, protected=lambda: {1})
        self.assertEqual(out.matched, 0)
        self.assertTrue(out.quiet)
        self.assertTrue(out.finished, "nothing was left running and it said otherwise")


class TestNothingIsLeftFrozen(unittest.TestCase):
    """A frozen process that is never ended and never resumed is stopped for good: the operator
    cannot restart it, it holds its files, and `ps` looks ordinary unless you read the state."""

    def _spawn(self):
        from stayawake.utils.procsnap import identify
        proc = subprocess.Popen(["/bin/sleep", "30"])
        self.addCleanup(self._kill, proc)
        for _ in range(50):
            who, _state = identify(proc.pid)
            if who is not None:
                return proc, who
            time.sleep(0.02)
        self.skipTest("the child never became readable")

    def _kill(self, proc):
        try:
            os.kill(proc.pid, 9)
            proc.wait(timeout=5)
        except Exception:
            pass

    def _state(self, pid):
        return subprocess.run(["ps", "-o", "state=", "-p", str(pid)],
                              capture_output=True, text=True).stdout.strip()

    @unittest.skipUnless(os.name == "posix", "needs POSIX signals")
    def test_a_grader_that_raises_mid_pass_leaves_nothing_stopped(self):
        proc, who = self._spawn()
        rounds = iter([[(Process(pid=proc.pid, argv=("node", "-e", "p"), identity=who), "p", "s")]])

        def find():
            batch = next(rounds, None)
            if batch is None:
                raise RuntimeError("the grader blew up on attacker-chosen text")
            return batch

        with self.assertRaises(RuntimeError):
            live.end_live_code(find=find, capture=lambda held, where: None,
                               protected=lambda: {1})
        self.assertNotEqual(self._state(proc.pid), "T", "it was left stopped for good")

    @unittest.skipUnless(os.name == "posix", "needs POSIX signals")
    def test_an_interrupt_mid_pass_leaves_nothing_stopped(self):
        proc, who = self._spawn()
        held = [(Process(pid=proc.pid, argv=("node", "-e", "p"), identity=who), "p", "s")]

        def capture(_held, _where):
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            live.end_live_code(find=lambda: held, capture=capture, protected=lambda: {1},
                               rounds=1)
        self.assertNotEqual(self._state(proc.pid), "T", "Ctrl-C left it stopped for good")


if __name__ == "__main__":
    unittest.main()
