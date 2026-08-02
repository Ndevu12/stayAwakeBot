#!/usr/bin/env python3
"""utils.progress — the concurrency-aware progress reporters behind a parallel `saw scan` (#1205).

Both reporters write to STDERR only; these tests drive them against an in-memory buffer.
"""
from __future__ import annotations

import io
import time
import unittest

from stayawake.utils.progress import LiveProgress, PlainProgress, make_progress


class TestPlainProgress(unittest.TestCase):
    def test_one_line_per_completion_with_running_counter(self):
        buf = io.StringIO()
        p = make_progress(enabled=False, out=buf, color=False)
        self.assertIsInstance(p, PlainProgress)
        p.start(3)
        p.item_started("a/b")                 # no live lines in plain mode
        p.item_done("a/b", "[clean   ]", "0 findings")
        p.item_done("c/d", "[INFECTED]", "2 findings")
        p.finish()
        out = buf.getvalue()
        self.assertIn("[1/3] [clean   ]  a/b  (0 findings)", out)
        self.assertIn("[2/3] [INFECTED]  c/d  (2 findings)", out)

    def test_plain_never_emits_ansi(self):
        buf = io.StringIO()
        p = make_progress(enabled=False, out=buf, color=False)
        p.start(1)
        p.item_done("a/b", "[clean   ]", "0 findings")
        p.finish()
        self.assertNotIn("\033[", buf.getvalue())


class TestLiveProgress(unittest.TestCase):
    def _run(self, *, color: bool) -> str:
        buf = io.StringIO()
        lp = LiveProgress(buf, color=color, interval=0.02)
        lp.start(4)
        lp.item_started("owner/repo-one")
        lp.item_started("owner/repo-two")
        time.sleep(0.05)
        lp.item_done("owner/repo-one", "[clean   ]", "0 findings")
        lp.item_started("owner/repo-three")
        lp.item_done("owner/repo-two", "[INFECTED]", "1 findings")
        time.sleep(0.05)
        lp.item_done("owner/repo-three", "[clean   ]", "0 findings")
        lp.item_done("owner/repo-four", "[SUSPECT ]", "3 findings")
        lp.finish()
        return buf.getvalue()

    def test_all_completions_recorded_in_order_with_counters(self):
        out = self._run(color=False)
        for repo in ("owner/repo-one", "owner/repo-two", "owner/repo-three", "owner/repo-four"):
            self.assertIn(repo, out)
        self.assertIn("[1/4]", out)
        self.assertIn("[4/4]", out)
        # The four completion lines must appear in completion order.
        order = [out.index(r) for r in
                 ("repo-one", "repo-two", "repo-three", "repo-four")]
        self.assertEqual(order, sorted(order))

    def test_region_is_erased_on_finish(self):
        out = self._run(color=False)
        # finish() wipes the live region (clear-to-end-of-screen), so no in-flight "scanning…"
        # line is left dangling as the final visible content.
        self.assertNotIn("Scanning 4/4", out.rstrip().splitlines()[-1] if out.rstrip() else "")
        self.assertIn("\033[J", out)          # an erase sequence was emitted

    def test_color_gating(self):
        self.assertIn("\033[", self._run(color=True))       # colour on → ANSI present
        # colour off → the only ANSI is cursor control, never a colour SGR like the LINK code
        self.assertNotIn("\033[1;36m", self._run(color=False))

    def test_header_shows_running_count_not_a_stuck_zero(self):
        # Regression: early in a sweep the header must show in-flight activity, not a bare "0/38"
        # that reads as stuck / as if it were counting completions.
        buf = io.StringIO()
        lp = LiveProgress(buf, color=False, interval=0.02)
        lp.start(38)
        for i in range(5):
            lp.item_started(f"owner/repo-{i}")
        time.sleep(0.06)                      # let the render thread draw a frame
        mid = buf.getvalue()
        lp.finish()
        self.assertIn("0 done", mid)          # nothing finished yet...
        self.assertIn("5 running", mid)       # ...but 5 are visibly in flight
        self.assertIn("38 repos", mid)

    def test_make_progress_picks_live_when_enabled(self):
        self.assertIsInstance(make_progress(enabled=True, out=io.StringIO(), color=False),
                              LiveProgress)

    def test_long_label_is_truncated_not_wrapped(self):
        buf = io.StringIO()
        lp = LiveProgress(buf, color=False, interval=0.02)
        lp.start(1)
        lp.item_started("x" * 500)            # far wider than any terminal
        time.sleep(0.05)
        lp.item_done("x" * 500, "[clean   ]", "0 findings")
        lp.finish()
        # No single emitted physical line should be absurdly long (width fallback is 80 off a TTY).
        longest = max((len(seg) for chunk in buf.getvalue().split("\n")
                       for seg in [chunk]), default=0)
        self.assertLess(longest, 200)


if __name__ == "__main__":
    unittest.main()
