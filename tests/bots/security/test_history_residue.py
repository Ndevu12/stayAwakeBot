#!/usr/bin/env python3
"""A payload the repository still stores is reported, and never moves the verdict.

`saw fix` adds a removal commit — it must not rewrite history — so the payload stays reachable and
one command puts it back. Reporting it is the point; gating on it would turn every correctly
remediated repository red and cost the exit code its meaning.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from support.gitrepo import GitSandbox                                   # noqa: E402
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

        def noisy(repo, args):
            res = real(repo, args)
            if res is not None and args[0] == "rev-list":
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
                               lambda root, limit=200_000: (real(root)[0], False)):
            note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("object budget", note)


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
        job = workers.LocalScanJob(str(repo), str(repo), ScanOptions(history=True),
                                   load_signatures(), [])
        self.assertTrue(any("still STORE a confirmed payload" in n
                            for n in workers.scan_local(job).result.notes))

    def test_without_the_flag_it_stays_silent(self):
        repo = self.new_repo()
        self.write(repo, "a.js", "// x\n")
        self.commit(repo, "one")
        from stayawake.bots.security.service import workers
        from stayawake.bots.security.signatures import load_signatures
        job = workers.LocalScanJob(str(repo), str(repo), ScanOptions(), load_signatures(), [])
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
