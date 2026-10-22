"""An editor can ask a running saw, and an unchanged folder is not scanned again."""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from unittest import mock

from stayawake.bots.mcp import identity, launch, worker
from stayawake.cli import main
from stayawake.utils import exitcodes


class TestAFolderCanBeNamed(unittest.TestCase):
    def test_a_change_is_a_different_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "readme.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("hello\n")
            before = identity.tree_identity(folder)
            self.assertIsNotNone(before)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("hello again\n")
            self.assertNotEqual(identity.tree_identity(folder), before)

    def test_a_link_cannot_be_named(self):
        with tempfile.TemporaryDirectory() as folder:
            target = os.path.join(folder, "readme.txt")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("hello\n")
            os.symlink(target, os.path.join(folder, "alias.txt"))
            self.assertIsNone(identity.tree_identity(folder))

    def test_a_missing_path_cannot_be_named(self):
        self.assertIsNone(identity.tree_identity(os.path.join(tempfile.gettempdir(), "saw-missing-folder")))


class TestARunningSawAnswers(unittest.TestCase):
    def _session(self) -> worker.Session:
        return worker.Session()

    def test_a_scan_is_the_scan_document(self):
        with tempfile.TemporaryDirectory() as folder:
            baseline = os.path.join(folder, "baseline.json")
            with open(os.path.join(folder, "readme.txt"), "w", encoding="utf-8") as handle:
                handle.write("hello\n")
            with mock.patch.dict(os.environ, {"SAW_AUTORUN_BASELINE": baseline}):
                answer = self._session().scan_paths([folder])
                direct = worker._scan_document([folder])
        self.assertIsNotNone(direct)
        self.assertEqual(answer["verdict"], "clean")
        self.assertEqual(
            {key: value for key, value in answer["document"].items() if key != "generated_at"},
            {key: value for key, value in direct.items() if key != "generated_at"})

    def test_an_unchanged_folder_is_not_scanned_again(self):
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, "readme.txt"), "w", encoding="utf-8") as handle:
                handle.write("hello\n")
            calls = {"n": 0}

            def once(paths):
                calls["n"] += 1
                return {"schema_version": 1, "any_infected": False, "any_error": False,
                        "any_suspicious": False, "any_residue": False}

            session = self._session()
            with mock.patch.object(worker, "_scan_document", once):
                first = session.scan_paths([folder])
                second = session.verdict(folder)
            self.assertEqual(calls["n"], 1)
            self.assertEqual(second, first)

    def test_a_link_is_scanned_again(self):
        with tempfile.TemporaryDirectory() as folder:
            target = os.path.join(folder, "readme.txt")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("hello\n")
            os.symlink(target, os.path.join(folder, "alias.txt"))
            calls = {"n": 0}

            def each(paths):
                calls["n"] += 1
                return {"schema_version": 1, "any_infected": False, "any_error": False,
                        "any_suspicious": False, "any_residue": False}

            session = self._session()
            with mock.patch.object(worker, "_scan_document", each):
                session.scan_paths([folder])
                session.scan_paths([folder])
            self.assertEqual(calls["n"], 2)

    def test_a_target_that_was_not_read_is_not_verified(self):
        answer = self._session().scan_paths(["/no/such/saw-folder"])
        self.assertEqual(answer["verdict"], "not verified")
        self.assertNotIn("clean", answer["verdict"])

    def test_an_empty_question_is_not_verified(self):
        session = self._session()
        self.assertEqual(session.scan_paths([]), {"verdict": "not verified"})
        self.assertEqual(session.verdict(""), {"verdict": "not verified"})

    def test_the_first_audit_stands(self):
        document = {"schema_version": 1, "rotation": {"verdict": "incomplete"}}
        session = self._session()
        with mock.patch.object(worker, "_audit_document", return_value=document) as audit:
            first = session.audit()
            second = session.audit()
            third = session.audit(again=True)
        self.assertEqual(audit.call_count, 2)
        self.assertEqual(first["verdict"], "incomplete")
        self.assertEqual(second, first)
        self.assertEqual(third["document"], document)

    def test_a_line_round_trip(self):
        incoming = io.StringIO(json.dumps(
            {"jsonrpc": "2.0", "id": 7, "method": "verdict", "params": {"path": ""}}) + "\n")
        outgoing = io.StringIO()
        self.assertEqual(worker.serve(incoming, outgoing), exitcodes.CLEAN)
        answer = json.loads(outgoing.getvalue())
        self.assertEqual(answer["id"], 7)
        self.assertEqual(answer["error"]["message"], "not verified")


class TestTheSessionProgram(unittest.TestCase):
    def test_a_missing_program_is_not_verified(self):
        with mock.patch.dict(os.environ, {"SAW_MCP_BIN": ""}, clear=False):
            os.environ.pop("SAW_MCP_BIN", None)
            with mock.patch("stayawake.bots.mcp.launch.shutil.which", return_value=None):
                self.assertIsNone(launch.session_binary())

    def test_the_command_does_not_call_a_missing_program_clean(self):
        stderr = io.StringIO()
        with mock.patch("stayawake.cli.commands.mcp.session_binary", return_value=None), \
                mock.patch("sys.stderr", stderr):
            self.assertEqual(main(["mcp"]), exitcodes.INCOMPLETE)
        text = stderr.getvalue()
        self.assertIn("not verified", text)
        self.assertNotIn("clean", text)


if __name__ == "__main__":
    unittest.main()
