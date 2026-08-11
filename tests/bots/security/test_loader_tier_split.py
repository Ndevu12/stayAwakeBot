#!/usr/bin/env python3
"""The loader-fingerprint tier split.

`build_content_sig` used to answer one question for six callers that ask two different ones, and it
ignored `confidence` entirely — so a signature graded `heuristic` still reached a CONFIRMED finding
through every consumer, and its declared tier meant nothing at the one place it decides an outcome.

Two callers, two failure directions, so two named entry points:

  * `build_confirmed_loader_check` — verdict corroboration. A heuristic shape must NOT be laundered
    into an accusation.
  * `build_any_loader_check` — the remediation safety gate. A heuristic shape MUST still block a
    "fixed" claim, because writing back a file that still carries a loader is worse than declining
    to fix it.

Tier grades how confidently we ACCUSE; it must not grade how carefully we CLEAN.
"""
from __future__ import annotations

import unittest

from stayawake.bots.security.matchers.base import (
    build_any_loader_check, build_confirmed_loader_check)
from stayawake.bots.security.models import HEURISTIC
from stayawake.bots.security.signatures import load_signatures


def _sigs() -> list[dict]:
    return [s for group in load_signatures().values() for s in group]


def _loaders() -> list[dict]:
    return [s for s in _sigs() if s.get("pattern") and s.get("category") == "code-loader"]


class TestTierSplit(unittest.TestCase):
    def test_the_db_actually_exercises_both_tiers(self):
        # Guard against a vacuous suite: if every loader were one tier, the split below would pass
        # for the wrong reason. Derived from the DB, never a hardcoded id list.
        tiers = {s.get("confidence") == HEURISTIC for s in _loaders()}
        self.assertEqual(tiers, {True, False},
                         "the loader set must contain BOTH tiers or these tests prove nothing")

    def test_confirmed_check_ignores_every_heuristic_fingerprint(self):
        confirmed = build_confirmed_loader_check(_sigs())
        heuristics = [s for s in _loaders() if s.get("confidence") == HEURISTIC]
        for sig in heuristics:
            hit = confirmed(_sample_matching(sig))
            self.assertNotEqual(hit, sig["id"],
                                f"{sig['id']} is heuristic but reached a confirmed verdict")

    def test_any_check_still_sees_every_heuristic_fingerprint(self):
        # The fail-closed half. A heuristic loader surviving an excision must still block the fix.
        any_check = build_any_loader_check(_sigs())
        for sig in [s for s in _loaders() if s.get("confidence") == HEURISTIC]:
            self.assertEqual(any_check(_sample_matching(sig)), sig["id"],
                             f"{sig['id']} would no longer block a 'fixed' claim")

    def test_confirmed_fingerprints_reach_both_checks(self):
        confirmed, any_check = build_confirmed_loader_check(_sigs()), build_any_loader_check(_sigs())
        for sig in [s for s in _loaders() if s.get("confidence") != HEURISTIC]:
            sample = _sample_matching(sig)
            self.assertEqual(confirmed(sample), sig["id"])
            self.assertEqual(any_check(sample), sig["id"])


class TestRealPayloadStillCaught(unittest.TestCase):
    """The regression that matters: retiring a dead fingerprint must not cost real detection."""

    # The captured loader's own shape — a seeded fromCharCode shuffle plus a `_$_` seed var. Both
    # are MECHANISM (what the loader does), not identifier names (which this family regenerates
    # every build), which is why they survive where a mangled-name fingerprint does not.
    REAL_LOADER_SHAPE = "var _$_1e42=String.fromCharCode(127);var lfL=_$_1e42[0];"

    def test_confirmed_check_still_fires_on_the_real_loader_shape(self):
        self.assertIsNotNone(build_confirmed_loader_check(_sigs())(self.REAL_LOADER_SHAPE))

    def test_the_minifier_collision_no_longer_reaches_a_verdict(self):
        # `Sfl(`/`sFl(` are ordinary 3-char mangled names emitted by minifiers; they used to reach
        # INFECTED on published software through the confirmed tier.
        confirmed = build_confirmed_loader_check(_sigs())
        for benign in ("function Sfl(t,e){return t}", "var q=sFl(a,b);", "SFL(1)"):
            self.assertIsNone(confirmed(benign), f"{benign!r} still reaches a confirmed verdict")

    def test_the_measured_stable_marker_is_confirmed(self):
        # Present in 34/35 decrypted revisions and in the captured argv; 0 FP over 16,315 real files.
        self.assertEqual(build_confirmed_loader_check(_sigs())("global['_V']='A8-2070'"),
                         "loader-global-v-marker")


def _sample_matching(sig: dict) -> str:
    """A minimal string the signature's own pattern matches — derived from the DB so a pattern
    change cannot leave a test asserting against a shape that no longer exists."""
    import re
    samples = {
        "loader-decoder-fn": "x = sfL(0)",
        "loader-clientcode-error": "failed to run clientCode: boom",
        "loader-fromcharcode-127": "String.fromCharCode(127)",
        "loader-seed-var": "var _$_1e42 =",
        "loader-global-v-marker": "global['_V']=",
        "loader-global-bang": "global['!'] =",
        "loader-require-hijack": "global[_$_1e42[0]] = require",
    }
    sample = samples.get(sig["id"])
    if sample is None:
        raise AssertionError(
            f"no sample for {sig['id']} — a new code-loader signature was added without one, so "
            f"the tier split is untested for it")
    assert re.search(sig["pattern"], sample, re.IGNORECASE), \
        f"sample for {sig['id']} no longer matches its own pattern"
    return sample


if __name__ == "__main__":
    unittest.main()
