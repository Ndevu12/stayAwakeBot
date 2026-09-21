#!/usr/bin/env python3
"""A payload the repository still stores is reported, and never moves the verdict.

`saw fix` adds a removal commit — it must not rewrite history — so the payload stays reachable and
one command puts it back. Reporting it is the point; gating on it would turn every correctly
remediated repository red and cost the exit code its meaning.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from stayawake.bots.security.matchers import symlink
from stayawake.bots.security.targets import history as history_target
from stayawake.lib.git import query
from stayawake.lib.git.query import stored_link_targets

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from support.gitrepo import GitSandbox                                   # noqa: E402
from stayawake.bots.security.resolution import LocalTarget, REPOSITORY
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security import scanner                             # noqa: E402
from stayawake.bots.security.models import (CLEAN, CONFIRMED,           # noqa: E402
                                             ScanReport, ScanResult)
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions          # noqa: E402
from stayawake.bots.security.targets.history import (HistoryTarget,               # noqa: E402
                                                     versions_by_path)


def _payload() -> str:
    """A CONFIRMED loader shape, split so this file carries no contiguous indicator."""
    cc = "from" + "CharCode"
    run = "ev" + "al"
    return f"const x = String.{cc}(127) + String.{cc}(127); {run}(x);\n"


class TestWhatHistoryStillCarries(GitSandbox):
    def _remediated(self):
        """The shape `saw fix` leaves: the payload lands, a removal commit cleans the tip."""
        repo = self.new_repo()
        self.write(repo, "index.js", "module.exports = 1;\n")
        self.commit(repo, "first")
        self.write(repo, "loader.js", _payload())
        self.commit(repo, "payload lands")
        (repo / "loader.js").unlink()
        self.commit(repo, "removal commit")
        return repo

    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def test_the_tree_really_is_clean(self):
        repo = self._remediated()
        result = scanner.scan_target(LocalRepoTarget(repo, str(repo), ScanOptions()),
                                     self._sigs(), [])
        self.assertEqual(result.verdict, CLEAN)

    def test_the_payload_is_still_stored_and_is_reported(self):
        repo = self._remediated()
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("still STORE a confirmed payload", note)
        self.assertIn("loader.js", note)

    def test_reporting_it_does_not_move_the_verdict(self):
        """The whole contract. A repository that was correctly remediated must not start failing:
        nothing stored in history runs on clone or on build."""
        repo = self._remediated()
        opts = ScanOptions(history=True)
        tree = scanner.scan_target(LocalRepoTarget(repo, str(repo), opts), self._sigs(), [])
        note = scanner.history_residue_note(repo, opts, self._sigs(), [])
        self.assertIn("loader.js", note, "it really did find one")
        self.assertEqual(tree.verdict, CLEAN, "and the verdict is untouched")
        self.assertEqual(tree.findings, [], "it is a note, never a finding")

    def test_a_repository_with_nothing_stored_says_so_rather_than_nothing(self):
        """Silence would read as 'not looked at'. The run said it read history, so it says what
        that established."""
        repo = self.new_repo()
        self.write(repo, "index.js", "module.exports = 1;\n")
        self.commit(repo, "only commit")
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("History was read", note)
        self.assertNotIn("still STORE", note)

    def test_a_history_it_could_not_finish_reading_is_not_reported_as_read(self):
        """A read that could not be established reports UNKNOWN, never no payload."""
        repo = self.new_repo()
        self.write(repo, "index.js", "module.exports = 1;\n")
        self.commit(repo, "only commit")
        opts, sigs = ScanOptions(history=True), self._sigs()
        settled = scanner.history_residue_note(repo, opts, sigs, [])
        self.assertIn("History was read:", settled)
        self.assertNotIn("UNKNOWN", settled)
        with mock.patch.object(query, "stored_link_targets", return_value=({}, False)):
            partial = scanner.history_residue_note(repo, opts, sigs, [])
        self.assertIn("UNKNOWN", partial, "an unestablished read still claimed no payload")
        self.assertNotIn("History was read:", partial)

    def test_a_stored_version_can_be_fetched_by_the_name_reported(self):
        """The path is the real one — an identity encoded into it defeats every allowlist glob and
        every extension match. The sha is asked for separately."""
        repo = self._remediated()
        versions, _ = versions_by_path(repo)
        target = HistoryTarget(repo, str(repo), ScanOptions(), versions)
        self.assertIn("loader.js", list(target.iter_files()), "the REAL path, so globs still match")
        self.assertEqual(target.read_bytes("loader.js").decode(), _payload())
        self.assertEqual(self.git(repo, "cat-file", "blob", target.sha_for("loader.js")), _payload())


class TestManyStoredVersionsOfOnePath(GitSandbox):
    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def _churned(self, versions: int, payload_at: int | None = None):
        repo = self.new_repo()
        for n in range(versions):
            body = _payload() if n == payload_at else f"// version {n}\n"
            self.write(repo, "churn.js", body)
            self.commit(repo, f"v{n}")
        self.write(repo, "churn.js", "// clean tip\n")
        self.commit(repo, "clean tip")
        return repo

    def test_a_payload_in_a_later_version_is_still_found(self):
        """One round per path would read only the newest stored version, so a payload three
        rewrites back would be missed while the run reported it had read history."""
        repo = self._churned(4, payload_at=1)
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("churn.js", note)

    def test_what_the_bound_cut_is_counted(self):
        """A bound that is not reported reads as coverage of what it cut."""
        repo = self._churned(6)
        with mock.patch.object(scanner, "_HISTORY_ROUNDS", 2):
            note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("were not read", note)
        self.assertIn("path(s)", note)

    def test_a_heuristic_shape_in_history_is_not_called_confirmed(self):
        """Confirmed only. A shape benign code shares, in a five-year-old commit, is a line the
        operator dismisses on every scan."""
        import base64
        import os as _os
        blob = base64.b64encode(_os.urandom(3000)).decode()
        repo = self.new_repo()
        self.write(repo, "min.js", f"var d='{blob}';\n")     # heuristic only: no confirmed signature
        self.commit(repo, "a minified-looking file")
        self.write(repo, "min.js", "// replaced\n")
        self.commit(repo, "replace it")
        versions, _ = versions_by_path(repo)
        found = []
        for index in range(3):
            target = HistoryTarget(repo, str(repo), ScanOptions(), versions, index)
            if not len(target):
                break
            found += scanner.scan_target(target, self._sigs(), []).findings
        self.assertTrue([f for f in found if f.confidence != CONFIRMED],
                        "the fixture must actually produce a heuristic finding")
        self.assertFalse([f for f in found if f.confidence == CONFIRMED])
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertNotIn("still STORE a confirmed payload", note)


class TestAnExcludedNameIsNotABlindSpot(GitSandbox):
    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def test_a_payload_also_filed_under_an_excluded_name_is_still_found(self):
        """This once excluded `node_modules/` and peers, to answer the same way the tree scan does.
        That is unsound here: `rev-list --objects` emits a blob ONCE, under one of its names, so
        excluding by that name drops content that also sits at a scanned path — and whoever
        committed it chooses which name git emits. Noise is the cheaper mistake."""
        repo = self.new_repo()
        self.write(repo, "src/loader.js", _payload())
        self.write(repo, "node_modules/x/index.js", _payload())      # same bytes, one blob
        self.write(repo, "app.js", "hello\n")
        self.commit(repo, "payload, also filed under an excluded name")
        (repo / "src" / "loader.js").unlink()
        (repo / "node_modules" / "x" / "index.js").unlink()
        self.commit(repo, "removed from the tree")
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("still STORE a confirmed payload", note)


class TestAnOversizedStoredVersionIsBoundedButStillScanned(GitSandbox):
    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def _repo_with_a_big_stored_blob(self, filler: bytes):
        repo = self.new_repo()
        (repo / "vendor.js").write_bytes(_payload().encode() + filler + _payload().encode())
        self.write(repo, "keep.txt", "ok\n")
        self.git(repo, "add", "-A")
        self.commit(repo, "an oversized version lands")
        (repo / "vendor.js").unlink()
        self.git(repo, "add", "-A")
        self.commit(repo, "removal commit")
        return repo

    def test_it_is_read_at_both_ends_rather_than_skipped(self):
        """Refusing it outright read the payload as empty while still counting it as scanned. The
        tree side reads an oversized file at both ends; so does this."""
        repo = self._repo_with_a_big_stored_blob(b"\n// filler\n" * 300_000)
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("vendor.js", note)

    def test_the_whole_version_is_never_held_in_memory(self):
        """A size test after the read cannot bound it — the read is what costs. The tree side stats
        before opening; a stored version has nothing to stat, so the cap moves into the read."""
        repo = self._repo_with_a_big_stored_blob(b"\n// filler\n" * 300_000)
        versions, _ = versions_by_path(repo)
        target = HistoryTarget(repo, str(repo), ScanOptions(), versions)
        stored = len(self.git(repo, "cat-file", "blob", target.sha_for("vendor.js")))
        held = len(target.read_text("vendor.js") or "")
        self.assertGreater(stored, ScanOptions().max_file_bytes, "the fixture must be oversized")
        self.assertLessEqual(held, ScanOptions().max_file_bytes + 1024,
                             "the whole stored version was materialised")


class TestTheReportCannotBeAimedByWhoeverCommitted(GitSandbox):
    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def _same_bytes_under_two_names(self, second: str):
        repo = self.new_repo()
        self.write(repo, "vendor/evil.js", _payload())
        self.write(repo, second, _payload())          # same bytes, so ONE blob with two names
        self.write(repo, "keep.txt", "ok\n")
        self.git(repo, "add", "-A")
        self.commit(repo, "payload under two names")
        (repo / "vendor" / "evil.js").unlink()
        (repo / second).unlink()
        self.git(repo, "add", "-A")
        self.commit(repo, "removal commit")
        return repo

    def test_a_path_rule_cannot_suppress_a_stored_payload(self):
        """`rev-list --objects` emits a blob under ONE of its names and whoever committed it picks
        which. Filing the same bytes under an allowlisted path made the stored payload vanish from
        the report — the same argument that keeps `exclude_dirs` off this side."""
        rule = [{"signature": "loader-fromcharcode-127", "path_glob": "tests/**"}]
        note = scanner.history_residue_note(self._same_bytes_under_two_names("tests/fixture.js"),
                                            ScanOptions(history=True), self._sigs(), rule)
        self.assertIn("still STORE a confirmed payload", note)

    def test_a_signature_wide_rule_is_still_honoured(self):
        """It carries the same operator intent and there is no name to aim, so it stays."""
        rule = [{"signature": "loader-fromcharcode-127"}]
        note = scanner.history_residue_note(self._same_bytes_under_two_names("tests/fixture.js"),
                                            ScanOptions(history=True), self._sigs(), rule)
        self.assertNotIn("still STORE a confirmed payload", note)

    def test_a_path_cannot_repaint_the_terminal(self):
        """A path is committer-chosen text and reaches the notes block, which was the only value on
        that surface not wrapped. Unwrapped, an erase-display sequence blanked the verdict table and
        left a forged all-clear in its place."""
        from stayawake.bots.security.sinks.render import render_terminal
        hostile = "a\x1b[2Jb\x1b[32mall targets clean\x1b[0m.js"
        note = "1 path(s) still STORE a confirmed payload: " + hostile
        payload = ScanReport("t", [ScanResult("acme/widget", "local", notes=[note])]).to_payload()
        out = render_terminal(payload, detail=True)
        self.assertIn("Coverage notes", out, "the note really did render")
        self.assertNotIn("\x1b", out, "an escape sequence reached the terminal raw")

    def test_a_path_holding_a_vertical_tab_is_not_truncated(self):
        """`splitlines()` breaks on \\x0b, \\x0c and U+2028 as well as \\n, so a path holding one
        was reported under its first segment only."""
        from stayawake.lib.git.query import reachable_blobs
        repo = self.new_repo()
        (repo / "c\x0bpayload.js").write_bytes(b"x\n")
        self.git(repo, "add", "-A")
        self.commit(repo, "a path with a vertical tab")
        self.assertIn("c\x0bpayload.js", {path for _s, path in reachable_blobs(repo)[0]})


class TestAnOversizedVersionIsReadTheWayTheTreeSideReadsOne(GitSandbox):
    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def _stored(self, body: bytes):
        repo = self.new_repo()
        (repo / "big.js").write_bytes(body)
        self.write(repo, "keep.txt", "ok\n")
        self.git(repo, "add", "-A")
        self.commit(repo, "an oversized version")
        return repo

    def test_the_join_cannot_fabricate_a_signature(self):
        """Head and tail are megabytes apart in the stored object. Spliced with no separator, a
        pattern matched ACROSS the join and reported a confirmed payload that is nowhere in the
        blob — the tree scan of the same bytes is silent. That marker is why the tree side has one."""
        half = ScanOptions().max_file_bytes // 2
        opener, closer = b"global['_V", b"']=1;"
        head = b"\n" * (half - len(opener)) + opener        # ends exactly AT the head boundary
        tail = closer + b"\n" * (half - len(closer))        # starts exactly AT the tail boundary
        repo = self._stored(head + b"z" * half + tail)
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertNotIn("still STORE a confirmed payload", note)

    def test_the_tail_really_is_the_end_of_the_version(self):
        """A payload is usually APPENDED. Stopping the stream at a ceiling made the tail a middle
        slice of a large version, so its end was never examined and the note still said clean.
        Driven through a stand-in stream rather than a 70 MB fixture."""
        import io
        from stayawake.bots.security.targets.history import HistoryTarget
        repo = self._stored(b"x\n")
        versions, _ = versions_by_path(repo)
        target = HistoryTarget(repo, "t", ScanOptions(), versions)
        half = ScanOptions().max_file_bytes // 2
        body = b"H" * half + b"M" * (200 * 1024 * 1024) + b"THE-REAL-END"

        class _Stream:
            returncode = 0
            stdout = io.BytesIO(body)

            def __enter__(self): return self
            def __exit__(self, *a): return False
            def kill(self): pass

        with mock.patch.object(HistoryTarget, "_cat_file", return_value=_Stream()):
            out = target._head_tail(list(versions)[0])
        self.assertTrue(out.endswith(b"THE-REAL-END"), "the tail was a middle slice, not the end")
        self.assertLessEqual(len(out), ScanOptions().max_file_bytes + 64, "and it stayed bounded")

    def test_an_appended_payload_at_the_very_end_is_found(self):
        repo = self._stored(b"// filler\n" * 400_000 + _payload().encode())
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("big.js", note)


class TestAnOrdinaryRepositoryIsNotAlarmed(GitSandbox):
    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def test_an_empty_file_is_not_an_unreadable_version(self):
        """A zero-byte blob is a legitimate `.gitkeep` / `py.typed` / empty `__init__.py`, and 5 of
        10 repositories on this host store one. Reading emptiness as failure printed a gap that was
        not there, and subtracted it from the count of versions examined."""
        repo = self.new_repo()
        (repo / ".gitkeep").write_bytes(b"")
        self.write(repo, "a.js", "// x\n")
        self.git(repo, "add", "-A")
        self.commit(repo, "an empty file, as every repository has")
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertNotIn("could not be read", note)

    def test_a_repository_with_no_commits_is_empty_not_unknown(self):
        """`complete` separates "git could not answer" from "there is genuinely nothing here"; the
        two were collapsed in the alarming direction, so a fresh repository raised a false gap."""
        note = scanner.history_residue_note(self.new_repo("fresh"), ScanOptions(history=True),
                                            self._sigs(), [])
        self.assertNotIn("UNKNOWN", note)
        self.assertIn("stores no earlier version", note)


class TestBothHalvesOfTheWalkAreBelieved(unittest.TestCase):
    def test_anything_the_walk_reports_makes_the_read_incomplete(self):
        """Two commands enumerate history and only one had its stderr read. I could not make
        `rev-list` exit 0 WITH stderr on this git, so this pins the contract rather than a
        reproduction: whatever either command complains about, the read is not called complete."""
        import subprocess as _sp
        from stayawake.lib.git import query as q
        real = q.run

        def noisy(repo, args, **kw):
            res = real(repo, args, **kw)
            if res is not None and "rev-list" in args:
                return _sp.CompletedProcess(args, 0, res.stdout, "warning: something was skipped\n")
            return res

        with mock.patch.object(q, "run", noisy), tempfile.TemporaryDirectory() as d:
            _sp.run(["git", "init", "-q", d], check=True)
            pathlib.Path(d, "a.js").write_text("// x\n")
            _sp.run(["git", "-C", d, "add", "-A"], check=True)
            _sp.run(["git", "-C", d, "-c", "user.email=a@b", "-c", "user.name=a",
                     "commit", "-qm", "x"], check=True, capture_output=True)
            self.assertFalse(q.reachable_blobs(d)[1])


class TestItSaysSoWhenItCouldNotRead(GitSandbox):
    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def test_a_repository_git_cannot_enumerate_is_unknown_not_clean(self):
        """`stdout` degrades a failed git command to an empty string, so "no objects" and "git
        could not answer" arrived identically and the run said nothing at all."""
        repo = self.new_repo()
        self.write(repo, "app.js", "hello\n")
        self.commit(repo, "first")
        (repo / ".git" / "refs" / "heads" / "broken").write_text("0" * 40 + "\n")
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIsNotNone(note, "silence is the failure this note exists to end")
        self.assertIn("UNKNOWN", note)

    def test_a_version_that_could_not_be_read_is_not_counted_as_read(self):
        """`read_errors` were collected on the target and then dropped, so an unreadable stored
        object was counted in the number the note reports as examined."""
        repo = self.new_repo()
        self.write(repo, "a.js", "// one\n")
        self.commit(repo, "one")
        from stayawake.bots.security.targets.history import HistoryTarget
        with mock.patch.object(HistoryTarget, "_cat_file", side_effect=OSError("boom")):
            note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("1 stored version(s) could not be read", note)
        self.assertNotIn("-", note.split("payload in")[1][:12],
                         "one version read five times is one unreadable version, not five")

    def test_a_truncated_walk_is_not_reported_as_a_completed_read(self):
        repo = self.new_repo()
        for n in range(4):
            self.write(repo, f"f{n}.js", f"// {n}\n")
            self.commit(repo, f"c{n}")
        from stayawake.bots.security.targets import history as hist
        real = hist.versions_by_path
        with mock.patch.object(hist, "versions_by_path",
                               lambda root, limit=200_000, offline=True: (real(root)[0], False)):
            note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("Not all of what it stores could be enumerated", note)


class TestEveryLocalTargetGetsIt(GitSandbox):
    def test_a_fleet_scan_reads_history_too(self):
        """It was wired into the single-repository path only, so `--history` over more than one
        repository was a silent no-op: the run reported it had read history and had not."""
        from stayawake.bots.security.service import workers
        from stayawake.bots.security.signatures import load_signatures
        repo = self.new_repo()
        self.write(repo, "loader.js", _payload())
        self.commit(repo, "payload lands")
        (repo / "loader.js").unlink()
        self.commit(repo, "removal commit")
        job = workers.LocalScanJob(LocalTarget(repo, None, REPOSITORY), str(repo),
                                   ScanOptions(history=True), load_signatures(), [])
        self.assertTrue(any("still STORE a confirmed payload" in n
                            for n in workers.scan_local(job).result.notes))

    def test_without_the_flag_it_stays_silent(self):
        repo = self.new_repo()
        self.write(repo, "a.js", "// x\n")
        self.commit(repo, "one")
        from stayawake.bots.security.service import workers
        from stayawake.bots.security.signatures import load_signatures
        job = workers.LocalScanJob(LocalTarget(repo, None, REPOSITORY), str(repo),
                                   ScanOptions(), load_signatures(), [])
        self.assertFalse([n for n in workers.scan_local(job).result.notes if "History" in n])


class TestARemoteTargetIsRefusedRatherThanHalfAnswered(unittest.TestCase):
    def test_history_with_remote_says_why_instead_of_doing_nothing(self):
        """A remote target is fetched shallow, so its history is not there. Doing nothing silently
        is the failure this whole feature exists to fix."""
        import io, contextlib
        from stayawake.cli import main
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = main(["scan", "--history", "--remote", "owner/name"])
        self.assertNotEqual(rc, 0)
        self.assertIn("shallow", err.getvalue())


if __name__ == "__main__":
    unittest.main()


class TestAStoredSymlinkIsStillRead(GitSandbox):
    """A symlink is stored as a blob holding its target, so history reads it like any other."""

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("links", user__name="T", user__email="t@t.test")
        self.write(self.d, "seed.txt", "seed\n")
        self.commit(self.d, "seed")
        self.base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()

    def _stored_in(self, root):
        """The confirmed findings a scan of `root`'s stored versions reports."""
        from stayawake.bots.security.targets.history import HistoryTarget, versions_by_path
        versions, _complete = versions_by_path(root)
        target = HistoryTarget(root, str(root), ScanOptions(), versions, 0,
                               stored_link_targets(root)[0])
        return [f for f in scanner.scan_target(target, load_signatures(), []).findings
                if f.confidence == CONFIRMED]

    def _stored_all_rounds(self):
        from stayawake.bots.security.targets.history import HistoryTarget, versions_by_path
        versions, _complete = versions_by_path(self.d)
        out = []
        for index in range(20):
            target = HistoryTarget(self.d, str(self.d), ScanOptions(), versions, index,
                                   stored_link_targets(self.d)[0] if index == 0 else {})
            if not len(target):
                break
            out += [f for f in scanner.scan_target(target, load_signatures(), []).findings
                    if f.confidence == CONFIRMED]
        return out

    def _stored(self):
        from stayawake.bots.security.targets.history import HistoryTarget, versions_by_path
        versions, _complete = versions_by_path(self.d)
        target = HistoryTarget(self.d, str(self.d), ScanOptions(), versions, 0,
                               stored_link_targets(self.d)[0])
        return [f for f in scanner.scan_target(target, load_signatures(), []).findings
                if f.confidence == CONFIRMED]

    def _commit_link(self, rel, target):
        import os
        os.makedirs(os.path.dirname(os.path.join(str(self.d), rel)), exist_ok=True)
        os.symlink(target, os.path.join(str(self.d), rel))
        self.git(self.d, "add", "-A")
        self.commit(self.d, f"add {rel}")
        os.remove(os.path.join(str(self.d), rel))
        self.git(self.d, "add", "-A")
        self.commit(self.d, f"remove {rel} from the tree")

    def test_a_write_redirect_no_longer_in_the_tree_is_still_stored(self):
        """A version the working tree no longer holds is still graded."""
        self._commit_link("tools/postinstall",
                          os.path.join(str(Path.home()), ".ssh", "authorized_keys"))
        found = [(f.signature_id, f.path) for f in self._stored()]
        self.assertIn(("symlink-write-redirect", "tools/postinstall"), found)

    def test_an_alias_on_disk_does_not_excuse_a_stored_redirect(self):
        """An uncommitted symlink in the checkout does not excuse a stored redirect."""
        self._commit_link("a/hook", "../../beside/.ssh/authorized_keys")
        shutil.rmtree(os.path.join(str(self.d), "a"), ignore_errors=True)
        os.symlink("x/y", os.path.join(str(self.d), "a"))
        inside = os.path.realpath(os.path.join(str(self.d), "a", "hook", "..", "..",
                                               "beside", ".ssh", "authorized_keys"))
        self.assertTrue(inside.startswith(os.path.realpath(str(self.d)) + os.sep),
                        "the alias must make realpath land inside, or nothing is being excused")
        self.assertIn(("symlink-write-redirect", "a/hook"),
                      [(f.signature_id, f.path) for f in self._stored()])

    def test_a_committed_alias_does_not_suppress_a_stored_redirect(self):
        """Two repositories storing the same link answer the same, whatever else either commits."""
        self._commit_link("a/hook", "../../evil/.ssh/authorized_keys")
        bare = [(f.signature_id, f.path) for f in self._stored()]
        shutil.rmtree(os.path.join(str(self.d), "a"), ignore_errors=True)
        os.symlink("x/y", os.path.join(str(self.d), "a"))
        self.git(self.d, "add", "-A")
        self.commit(self.d, "add a workspace alias")
        self.assertIn(("symlink-write-redirect", "a/hook"), bare)
        self.assertIn(("symlink-write-redirect", "a/hook"),
                      [(f.signature_id, f.path) for f in self._stored()])

    def test_a_tree_mounted_twice_is_graded_at_each_depth(self):
        """A tree stored at two depths is graded at each of them."""
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=b"../../.ssh/authorized_keys",
                              capture_output=True).stdout.decode().strip()
        for at in ("shallow", "d1/d2"):
            self.git(self.d, "update-index", "--add", "--cacheinfo", f"120000,{blob},{at}/hook")
        tree = self.git(self.d, "write-tree").strip()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        sha = self.git(self.d, "commit-tree", tree, "-p", head, "-m", "mount it twice").strip()
        self.git(self.d, "update-ref", "HEAD", sha)
        mounts = {self.git(self.d, "rev-parse", f"{sha}:{at}").strip()
                  for at in ("shallow", "d1/d2")}
        self.assertEqual(1, len(mounts), "the two mounts must be one tree object, or this is not "
                                         "the shape that is being pinned")
        at_path, complete = stored_link_targets(self.d)
        self.assertTrue(complete)
        self.assertEqual({"shallow/hook", "d1/d2/hook"}, set(at_path),
                         "a tree mounted twice was enumerated at one of its paths")
        self.assertIn(("symlink-write-redirect", "shallow/hook"),
                      [(f.signature_id, f.path) for f in self._stored()])

    def test_a_file_sharing_the_links_bytes_does_not_hide_it(self):
        """A file sharing a link's bytes does not hide the link."""
        target = os.path.join(str(Path.home()), ".ssh", "authorized_keys")
        self.write(self.d, "aaa_notes.txt", target)
        self.commit(self.d, "a file whose content is the target, sorting first")
        self._commit_link("hook", target)
        found = [(f.signature_id, f.path) for f in self._stored_all_rounds()]
        self.assertIn(("symlink-write-redirect", "hook"), found)

    def test_what_sits_beside_a_clone_does_not_decide_its_verdict(self):
        """Two clones of one repository answer the same, whatever sits beside each."""
        self._commit_link("cfg", "../beside/.aws/credentials")
        here = os.path.dirname(str(self.d))
        verdicts = []
        for name, plant in (("clone_a", False), ("clone_b", True)):
            root = os.path.join(here, name)
            self.git(self.d, "clone", "-q", str(self.d), root)
            beside = os.path.join(here, "beside")
            if os.path.lexists(beside):
                os.remove(beside)
            if plant:
                os.symlink(os.path.join(str(Path.home()), ".aws"), beside)
            verdicts.append(sorted(f.signature_id for f in self._stored_in(Path(root))))
        self.assertEqual(["symlink-write-redirect"], verdicts[0],
                         "the target must reach a sink, or neither clone can answer anything")
        self.assertEqual(verdicts[0], verdicts[1],
                         "what sat beside the clone changed its verdict")

    def _tree_with(self, mode: bytes, name: bytes, oid: str) -> str:
        """Write a tree holding one entry, exactly as spelled. Takes the mode, the name and the
        object it points at. Returns the new tree's id."""
        body = mode + b" " + name + b"\0" + bytes.fromhex(oid)
        return subprocess.run(["git", "-C", str(self.d), "hash-object", "-t", "tree", "-w",
                               "--literally", "--stdin"], input=body,
                              capture_output=True).stdout.decode().strip()

    def _commit_tree(self, tree: str) -> str:
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        sha = self.git(self.d, "commit-tree", tree, "-p", head, "-m", "as spelled").strip()
        self.git(self.d, "update-ref", "HEAD", sha)
        return sha

    def test_a_mode_is_read_as_the_type_git_gives_it(self):
        """A symlink entry spelled with a leading zero is still a symlink."""
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=b"../../../.ssh/authorized_keys",
                              capture_output=True).stdout.decode().strip()
        sub = self._tree_with(b"0120000", b"hook", blob)
        self._commit_tree(self._tree_with(b"40000", b"sub", sub))
        at_path, complete = stored_link_targets(self.d)
        self.assertTrue(complete)
        self.assertEqual(["sub/hook"], sorted(at_path))

    def test_a_subtree_spelled_unusually_is_not_silently_skipped(self):
        """A directory entry git reads as a tree is walked, and one it does not is not read as
        empty."""
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=b"../../../.ssh/authorized_keys",
                              capture_output=True).stdout.decode().strip()
        sub = self._tree_with(b"120000", b"hook", blob)
        self._commit_tree(self._tree_with(b"040000", b"sub", sub))
        at_path, complete = stored_link_targets(self.d)
        self.assertEqual(["sub/hook"], sorted(at_path))
        self.assertTrue(complete)

    def test_an_entry_naming_no_type_is_not_read_as_nothing(self):
        """An entry whose mode names no type git records leaves the read unestablished."""
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=b"x\n", capture_output=True).stdout.decode().strip()
        self._commit_tree(self._tree_with(b"000000", b"odd", blob))
        _at_path, complete = stored_link_targets(self.d)
        self.assertFalse(complete, "an entry naming no type was read as nothing")

    def test_a_subtree_that_cannot_be_read_is_not_read_as_empty(self):
        """A directory whose object the repository does not hold leaves the read unestablished."""
        self._commit_tree(self._tree_with(b"40000", b"sub", "0" * 40))
        _at_path, complete = stored_link_targets(self.d)
        self.assertFalse(complete, "a subtree that could not be read was read as empty")

    def test_a_batch_that_ends_early_is_not_read_as_complete(self):
        """A read that returns fewer objects than were asked for leaves the read unestablished."""
        self.write(self.d, "a/b/keep", "x\n")
        self.commit(self.d, "two levels")
        one = self.git(self.d, "rev-parse", "HEAD^{tree}").strip()
        whole = subprocess.run(["git", "-C", str(self.d), "cat-file", "--batch"],
                               input=one.encode(), capture_output=True).stdout
        with mock.patch.object(query, "stdout_bytes_fed", return_value=whole):
            entries, complete = query._read_trees(self.d, sorted([one, "b" * 40]))
        self.assertIn(one, entries, "the object that WAS returned must still be read")
        self.assertFalse(complete, "a read that answered for fewer objects was read as complete")

    _SIG = {"id": "symlink-write-redirect", "category": "c", "severity": "4", "description": "d"}

    def test_a_target_climbing_far_past_the_root_still_escapes(self):
        """A target that climbs further than the repository is deep has left it."""
        self.assertTrue(symlink._stored_finding("a/hook", "../../../app/.ssh/authorized_keys",
                                                {}, self._SIG))

    def test_a_target_is_followed_through_the_links_the_repository_stores(self):
        """A checkout walks the links it restores, so grading one reads the others."""
        stored = {"hop": ["/"], "link": ["hop/Users/v/.ssh/authorized_keys"]}
        self.assertTrue(symlink._stored_finding("link", stored["link"][0], stored, self._SIG),
                        "a target reaching its sink through another stored link was missed")
        relative = {"pkg/up": ["../../../../.."], "pkg/k": ["up/Users/v/.ssh/authorized_keys"]}
        self.assertTrue(symlink._stored_finding("pkg/k", relative["pkg/k"][0], relative, self._SIG))

    def test_a_chain_longer_than_a_checkout_follows_still_escapes(self):
        """A chain a checkout is willing to follow is followed for as far as it goes."""
        deep = {f"h{n}": [f"h{n + 1}"] for n in range(30)}
        deep["h30"] = ["/Users/v/.ssh/authorized_keys"]
        self.assertTrue(symlink._stored_finding("h0", deep["h0"][0], deep, self._SIG),
                        "a chain shorter than a checkout would follow was given up on")

    def test_a_chain_that_cannot_be_settled_is_still_reported(self):
        """A target the walk gave up following is judged on the path it names."""
        stored = {"a": ["b"], "b": ["c"], "c": ["inside/here"]}
        raw = "a/../../.ssh/authorized_keys"
        landings = symlink._landings("start", raw, stored, budget=1)
        self.assertEqual({("/.ssh/authorized_keys", True)}, landings,
                         "a chain the walk gave up on left nothing to judge")

    def test_a_target_is_read_the_way_a_checkout_reads_it(self):
        """A stored target ends where the system stops reading it."""
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=b"/Users/v/.zshrc\0.md", capture_output=True
                              ).stdout.decode().strip()
        self.git(self.d, "update-index", "--add", "--cacheinfo", f"120000,{blob},readme.md")
        tree = self.git(self.d, "write-tree").strip()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        sha = self.git(self.d, "commit-tree", tree, "-p", head, "-m", "a padded target").strip()
        self.git(self.d, "update-ref", "HEAD", sha)
        self.assertEqual(["/Users/v/.zshrc"], stored_link_targets(self.d)[0]["readme.md"])
        self.assertIn(("symlink-write-redirect", "readme.md"),
                      [(f.signature_id, f.path) for f in self._stored()])

    def test_the_repository_scanned_is_the_one_named(self):
        """The repository a scan answers about is the one it was given."""
        self._commit_link("ctl", os.path.join(str(Path.home()), ".ssh", "authorized_keys"))
        elsewhere = self.new_repo("elsewhere")
        self.write(elsewhere, "a.txt", "nothing\n")
        self.commit(elsewhere, "only commit")
        with mock.patch.dict(os.environ, {"GIT_DIR": os.path.join(str(elsewhere), ".git")}):
            at_path, complete = stored_link_targets(self.d)
        self.assertTrue(complete)
        self.assertIn("ctl", at_path, "the scan answered about a repository nobody named")

    def test_a_tag_chain_does_not_hide_what_it_reaches(self):
        """A tree reached only through a tag that points at another tag is still read."""
        self.git(self.d, "checkout", "-q", "-b", "side")
        os.symlink(os.path.join(str(Path.home()), ".ssh", "authorized_keys"),
                   os.path.join(str(self.d), "evil"))
        self.git(self.d, "add", "-A")
        self.commit(self.d, "the link, on a branch that goes away")
        tree = self.git(self.d, "rev-parse", "HEAD^{tree}").strip()
        self.git(self.d, "checkout", "-q", "--force", self.base)
        self.git(self.d, "branch", "-q", "-D", "side")
        self.git(self.d, "tag", "-a", "-m", "inner", "inner", tree)
        inner = self.git(self.d, "rev-parse", "refs/tags/inner").strip()
        self.git(self.d, "tag", "-a", "-m", "outer", "outer", inner)
        self.git(self.d, "tag", "-d", "inner")
        self.assertEqual([], [ln for ln in self.git(self.d, "rev-list", "--all").splitlines()
                              if ln.strip() == tree], "the tree must be reachable only by the tag")
        at_path, complete = stored_link_targets(self.d)
        self.assertTrue(complete)
        self.assertIn("evil", at_path)

    def test_a_configured_view_of_history_does_not_decide_what_is_stored(self):
        """History is read from the objects a repository holds, not from a view configured over
        them."""
        self._commit_link("evil", "../../../.ssh/authorized_keys")
        first = self.git(self.d, "rev-parse", "HEAD~2").strip()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        info = pathlib.Path(str(self.d), ".git", "info")
        info.mkdir(parents=True, exist_ok=True)
        (info / "grafts").write_text(f"{tip} {first}\n")
        self.git(self.d, "config", "advice.graftFileDeprecated", "false")
        self.assertEqual(2, len(self.git(self.d, "rev-list", "--all").split()),
                         "the view must really hide the commit that carries it")
        at_path, complete = stored_link_targets(self.d)
        self.assertTrue(complete)
        self.assertIn("evil", at_path)

    def test_a_stored_link_is_read_even_where_no_blob_version_is(self):
        """The stored links are read whatever the blob walk returned."""
        self._commit_link("hook", os.path.join(str(Path.home()), ".ssh", "authorized_keys"))
        opts, sigs = ScanOptions(history=True), load_signatures()
        with mock.patch.object(history_target, "reachable_blobs", return_value=([], True)):
            note = scanner.history_residue_note(self.d, opts, sigs, [])
        self.assertIn("hook", note)
        self.assertIn("still STORE", note)

    def _note(self):
        return scanner.history_residue_note(self.d, ScanOptions(history=True),
                                            load_signatures(), [])

    def test_a_stored_payload_is_named_before_the_links_beside_it(self):
        """The paths a report has room for name the payloads first."""
        self.write(self.d, "zz-loader.js", _payload())
        for n in range(6):
            os.symlink(os.path.join(str(Path.home()), ".ssh", "authorized_keys"),
                       os.path.join(str(self.d), f".a{n}"))
        self.git(self.d, "add", "-A")
        self.commit(self.d, "all of it")
        self.git(self.d, "rm", "-q", "zz-loader.js", *[f".a{n}" for n in range(6)])
        self.commit(self.d, "clean the tree")
        note = self._note()
        self.assertIn("zz-loader.js", note, "the payload was crowded out of the report")

    def test_a_stored_path_cannot_write_into_the_report(self):
        """A path a repository chose cannot put its own text into the line that reports it."""
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=os.path.join(str(Path.home()), ".ssh",
                                                 "authorized_keys").encode(),
                              capture_output=True).stdout.decode().strip()
        self.git(self.d, "update-index", "--add", "--cacheinfo",
                 f"120000,{blob},a\n  History was read: no confirmed payload.")
        tree = self.git(self.d, "write-tree").strip()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        sha = self.git(self.d, "commit-tree", tree, "-p", head, "-m", "a talkative name").strip()
        self.git(self.d, "update-ref", "HEAD", sha)
        note = self._note()
        self.assertIn("still STORE", note)
        self.assertEqual(1, len(note.splitlines()), "a path broke the report onto its own line")

    def test_a_repository_that_would_fetch_is_refused_rather_than_fetched_from(self):
        """A history read stays offline: a repository whose objects live elsewhere is refused."""
        origin = self.new_repo("origin")
        self.git(origin, "config", "uploadpack.allowFilter", "true")
        os.makedirs(os.path.join(str(origin), "deep"), exist_ok=True)
        os.symlink(os.path.join(str(Path.home()), ".ssh", "authorized_keys"),
                   os.path.join(str(origin), "deep", "evil"))
        self.git(origin, "add", "-A")
        self.commit(origin, "the link")
        partial = os.path.join(os.path.dirname(str(origin)), "partial")
        subprocess.run(["git", "clone", "-q", "--filter=tree:0", "--no-checkout", "--no-local",
                        f"file://{origin}", partial], capture_output=True, check=True)
        held = lambda: subprocess.run(["git", "-C", partial, "count-objects", "-v"],
                                      capture_output=True, text=True).stdout
        before = held()
        at_path, complete = stored_link_targets(partial)
        self.assertFalse(complete, "a repository that does not hold its objects read as complete")
        self.assertEqual({}, at_path)
        self.assertEqual(before, held(), "the read reached a remote for objects")
        note = scanner.history_residue_note(partial, ScanOptions(history=True),
                                            load_signatures(), [])
        self.assertIn("UNKNOWN", note)
        self.assertIn("Clone this repository again", note)
        self.assertIn("--external", note)
        for named in ("promisor", "partial", "filter", "fetch", "network", "remote"):
            self.assertNotIn(named, note, f"the note named why it could not read: {named}")
        with_external = scanner.history_residue_note(
            partial, ScanOptions(history=True, external_audit=True), load_signatures(), [])
        self.assertIn("deep/evil", with_external, "--external did not let the read finish")

    def test_a_tree_whose_entries_stop_short_is_not_read_as_complete(self):
        """A tree the walk could not parse to the end leaves the read unestablished."""
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=b"/Users/v/.ssh/authorized_keys",
                              capture_output=True).stdout.decode().strip()
        body = b"120000 visible\0" + bytes.fromhex(blob) + b"120000noseparator"
        tree = subprocess.run(["git", "-C", str(self.d), "hash-object", "-t", "tree", "-w",
                               "--literally", "--stdin"], input=body,
                              capture_output=True).stdout.decode().strip()
        self._commit_tree(tree)
        at_path, complete = stored_link_targets(self.d)
        self.assertIn("visible", at_path)
        self.assertFalse(complete, "a tree that stopped parsing was read as fully read")

    def test_a_replacement_object_does_not_answer_for_the_ref(self):
        """A ref is graded on what it stores, not on what a replacement object substitutes."""
        self._commit_link("hook", "../../../.ssh/authorized_keys")
        carrying = self.git(self.d, "rev-parse", "HEAD").strip()
        self.write(self.d, "ok.txt", "nothing here\n")
        self.git(self.d, "add", "-A")
        self.commit(self.d, "a clean twin")
        twin = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/heads/release", carrying)
        self.git(self.d, "replace", carrying, twin)
        at_path, _ = stored_link_targets(self.d)
        self.assertIn("hook", at_path)

    def test_a_version_that_cannot_be_established_is_not_read_as_inside(self):
        """A stored target too long to read is reported as unestablished, never as one inside."""
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=b"a" * 9000, capture_output=True).stdout.decode().strip()
        self.git(self.d, "update-index", "--add", "--cacheinfo", f"120000,{blob},huge")
        tree = self.git(self.d, "write-tree").strip()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        sha = self.git(self.d, "commit-tree", tree, "-p", head, "-m", "an unreadable target").strip()
        self.git(self.d, "update-ref", "HEAD", sha)
        at_path, complete = stored_link_targets(self.d)
        self.assertNotIn("huge", at_path)
        self.assertFalse(complete, "a version that was never read was reported as established")

    def test_where_a_clone_sits_does_not_decide_its_verdict(self):
        """Two clones of one repository answer the same, wherever each sits."""
        self._commit_link("doc", "../otherplugin/doc")
        here = os.path.dirname(str(self.d))
        verdicts = []
        for under in ("plain", os.path.join(".vim", "pack", "plugins", "start")):
            root = os.path.join(here, under, "pkg")
            os.makedirs(os.path.dirname(root), exist_ok=True)
            self.git(self.d, "clone", "-q", str(self.d), root)
            verdicts.append(sorted(f.signature_id for f in self._stored_in(Path(root))))
        self.assertEqual(verdicts[0], verdicts[1],
                         "the directory the clone sits under changed its verdict")

    def test_a_target_is_graded_as_it_is_stored(self):
        """A stored target is graded exactly as stored, whitespace included."""
        keys = os.path.join(str(self.d), "a", ".ssh")
        os.makedirs(keys, exist_ok=True)
        self.write(self.d, "a/.ssh/authorized_keys", "the repository's own fixture\n")
        self.commit(self.d, "add the fixture")
        blob = subprocess.run(["git", "-C", str(self.d), "hash-object", "-w", "--stdin"],
                              input=b"   ../../../../.ssh/authorized_keys",
                              capture_output=True).stdout.decode().strip()
        self.git(self.d, "update-index", "--add", "--cacheinfo",
                 f"120000,{blob},a/b/c/hook")
        tree = self.git(self.d, "write-tree").strip()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        sha = self.git(self.d, "commit-tree", tree, "-p", head, "-m", "a spaced target").strip()
        self.git(self.d, "update-ref", "HEAD", sha)
        self.assertEqual([], [f.signature_id for f in self._stored_in(self.d)])

    def test_a_file_named_like_a_mode_is_not_read_as_one(self):
        """A name is content, not structure: a repository storing no symlink reports none."""
        self.write(self.d, "report 2026-09-21 120000 rows.csv",
                   os.path.join(str(Path.home()), ".ssh", "authorized_keys"))
        self.commit(self.d, "an ordinary noon timestamp in a file name")
        self.assertEqual([], [(f.signature_id, f.path) for f in self._stored_all_rounds()])

    def test_every_target_a_link_ever_had_is_still_stored(self):
        """Every target a link ever had is graded, in either commit order."""
        for first_is_sink in (True, False):
            with self.subTest(sink_first=first_is_sink):
                d = self.new_repo(f"retarget{first_is_sink}", user__name="T",
                                  user__email="t@t.test")
                self.write(d, "lib/x", "x\n")
                self.commit(d, "the file it is sometimes pointed at")
                sink = os.path.join(str(Path.home()), ".ssh", "authorized_keys")
                for target in ((sink, "lib/x") if first_is_sink else ("lib/x", sink)):
                    link = os.path.join(str(d), "hook")
                    if os.path.lexists(link):
                        os.remove(link)
                    os.symlink(target, link)
                    self.git(d, "add", "-A")
                    self.commit(d, "point it")
                os.remove(os.path.join(str(d), "hook"))
                self.git(d, "add", "-A")
                self.commit(d, "remove it from the tree")
                found = [f.signature_id for f in self._stored_in(d)]
                self.assertIn("symlink-write-redirect", found)

    def test_a_link_only_a_merge_introduced_is_still_stored(self):
        """A link recorded in the merge's own tree and in neither parent was still stored."""
        self.git(self.d, "checkout", "-qb", "side")
        self.write(self.d, "side.js", "ok\n")
        self.commit(self.d, "work on the side branch")
        self.git(self.d, "checkout", "-q", self.base)
        self.write(self.d, "app.js", "ok\n")
        self.commit(self.d, "work on the base branch")
        self.git(self.d, "merge", "-q", "--no-ff", "--no-commit", "side")
        os.symlink(os.path.join(str(Path.home()), ".ssh", "authorized_keys"),
                   os.path.join(str(self.d), "hook"))
        self.git(self.d, "add", "-A")
        self.commit(self.d, "merge side, smuggling a link into the merge itself")
        os.remove(os.path.join(str(self.d), "hook"))
        self.git(self.d, "add", "-A")
        self.commit(self.d, "remove it from the tree")
        found = [(f.signature_id, f.path) for f in self._stored()]
        self.assertIn(("symlink-write-redirect", "hook"), found)
