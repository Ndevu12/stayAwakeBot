#!/usr/bin/env python3
"""Every JSON document saw prints says which schema it is written in, and `saw capabilities` tells a
program which documents and features this saw has, so it need not compare version numbers."""
from __future__ import annotations

import argparse
import io
import json
import socket
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from stayawake import cli
from stayawake.bots.security import remediator
from stayawake.bots.security.models import ScanReport
from stayawake.cli.commands import capabilities
from stayawake.utils import json_documents, scratch
from stayawake.utils.json_documents import SCHEMA_VERSION_OF_EACH_DOCUMENT, command_of, versioned

_PRINTS_A_LIST_NOT_A_DOCUMENT = {("search",)}


def _commands_that_take_json(parser, path=()):
    found = set()
    if path and capabilities.asks_for_json(parser):
        found.add(path)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            seen = set()
            for name, child in action._name_parser_map.items():
                if id(child) not in seen:
                    seen.add(id(child))
                    found |= _commands_that_take_json(child, (*path, name))
    return found


def _stdout_of(run):
    with mock.patch("stayawake.lib.auth.resolve_token", return_value=(None, None)), \
         redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
        run()
    return out.getvalue()


def _printed(argv):
    return json.loads(_stdout_of(lambda: cli.main(argv)))


def _fix_with_nothing_to_fix():
    with mock.patch.object(remediator, "_resolve_config", return_value={"settings": {}}), \
         mock.patch.object(remediator, "load_signatures", return_value={}), \
         mock.patch.object(remediator, "_fix_local", return_value=[]):
        remediator.fix(paths=["."], no_stream=True, json_out=True)


def _in_an_empty_folder(argv):
    folder = scratch.new_dir("an empty folder")
    with mock.patch("stayawake.bots.security.service.run.reports_dir_choice", return_value=None):
        return _stdout_of(lambda: cli.main([*argv, "--no-stream", str(folder)]))


def _audit_with_nothing_to_report():
    with mock.patch("stayawake.cli.commands.audit.hygiene.audit_checks", return_value=[]), \
         mock.patch("stayawake.bots.security.hygiene.document.live_process_scope_note",
                    return_value=""):
        cli.main(["audit", "--json", "--no-stream"])


def _drift_with_no_remote_repository():
    with mock.patch("stayawake.bots.security.guard.sweep.resolution.resolve_remote",
                    return_value=([], None, None)):
        return _stdout_of(lambda: cli.main(["guard", "drift", "--json", "--remote",
                                            "--no-stream"]))


_PRINT_EACH_DOCUMENT = {
    "scan": [lambda: _in_an_empty_folder(["scan", "--json"])],
    "fix": [lambda: _stdout_of(_fix_with_nothing_to_fix)],
    "doctor": [lambda: _stdout_of(lambda: cli.main(["doctor", "--json"]))],
    "auth-status": [lambda: _stdout_of(lambda: cli.main(["auth", "status", "--json"]))],
    "guard-drift": [lambda: _in_an_empty_folder(["guard", "drift", "--json"]),
                    _drift_with_no_remote_repository],
    "capabilities": [lambda: _stdout_of(lambda: cli.main(["capabilities", "--json"]))],
    "audit": [lambda: _stdout_of(_audit_with_nothing_to_report)],
}


def _tree(**commands):
    """Build top-level commands by name; a value is a dict of subcommands, or whether it takes
    `--json`."""
    def build(parser, spec):
        if isinstance(spec, dict):
            sub = parser.add_subparsers()
            for name, child in spec.items():
                build(sub.add_parser(name), child)
        elif spec:
            parser.add_argument("--json", action="store_true")
        return parser

    root = build(argparse.ArgumentParser(), commands)
    return next(a.choices for a in root._actions if isinstance(a, argparse._SubParsersAction))


class TestEveryJsonDocumentSaysItsSchema(unittest.TestCase):
    def test_asking_for_json_by_another_name_counts(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--machine", dest="json", action="store_true")
        self.assertTrue(capabilities.asks_for_json(parser))

    def test_every_command_that_prints_json_is_a_versioned_document(self):
        versioned_commands = {tuple(command_of(d)) for d in SCHEMA_VERSION_OF_EACH_DOCUMENT}
        self.assertEqual(_commands_that_take_json(cli.build_parser()),
                         versioned_commands | _PRINTS_A_LIST_NOT_A_DOCUMENT)

    def test_the_version_is_the_first_key_and_the_payload_is_kept(self):
        payload = {"results": []}
        stamped = versioned("fix", payload)
        self.assertEqual(list(stamped), ["schema_version", "results"])
        self.assertEqual(stamped["schema_version"], SCHEMA_VERSION_OF_EACH_DOCUMENT["fix"])
        self.assertEqual(payload, {"results": []})

    def test_every_document_prints_its_version_first(self):
        self.assertEqual(set(_PRINT_EACH_DOCUMENT), set(SCHEMA_VERSION_OF_EACH_DOCUMENT))
        for document, runs in _PRINT_EACH_DOCUMENT.items():
            for run, print_it in enumerate(runs):
                with self.subTest(document=document, run=run):
                    self._assert_versioned(document, json.loads(print_it()))

    def _assert_versioned(self, document, printed):
        self.assertEqual(next(iter(printed)), "schema_version")
        self.assertEqual(printed["schema_version"], SCHEMA_VERSION_OF_EACH_DOCUMENT[document])

    def test_the_saved_scan_report_carries_it(self):
        payload = ScanReport(generated_at="2026-10-21T00:00:00Z").to_payload()
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION_OF_EACH_DOCUMENT["scan"])


class TestCapabilities(unittest.TestCase):
    def test_it_names_every_document_saw_prints_and_its_feature(self):
        printed = _printed(["capabilities", "--json"])
        self.assertEqual(printed["schema_version"], SCHEMA_VERSION_OF_EACH_DOCUMENT["capabilities"])
        self.assertEqual(printed["schema_versions"], SCHEMA_VERSION_OF_EACH_DOCUMENT)
        self.assertEqual(printed["features"],
                         [".".join(command_of(d)) + ".json" for d in SCHEMA_VERSION_OF_EACH_DOCUMENT])
        self.assertTrue({"scan.json", "fix.json"} <= set(printed["features"]))
        self.assertEqual(printed["version"], cli.__version__)

    def _registry(self, **documents):
        return mock.patch.dict(json_documents.SCHEMA_VERSION_OF_EACH_DOCUMENT,
                               {"capabilities": 1, **documents}, clear=True)

    def test_a_document_is_offered_only_once_its_command_takes_json(self):
        with self._registry(scan=1, **{"hook-status": 2}):
            before = capabilities.capabilities(_tree(scan=True, hook={"status": False}))
            after = capabilities.capabilities(_tree(scan=True, hook={"status": True}))
        self.assertEqual(before["schema_versions"], {"scan": 1})
        self.assertEqual(before["features"], ["scan.json"])
        self.assertEqual(after["schema_versions"], {"scan": 1, "hook-status": 2})
        self.assertEqual(after["features"], ["scan.json", "hook.status.json"])

    def test_a_document_whose_command_does_not_exist_is_not_offered(self):
        with self._registry(audit=1):
            self.assertEqual(capabilities.capabilities(_tree(scan=True))["features"], [])

    def test_it_runs_without_the_network(self):
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
            self.assertIn("features", _printed(["capabilities", "--json"]))

    def test_it_says_whether_saw_supports_the_platform(self):
        for platform, supported in (("linux", True), ("darwin", True), ("win32", False)):
            with self.subTest(platform=platform), mock.patch("sys.platform", platform):
                self.assertEqual(capabilities.capabilities({})["platform"],
                                 {"os": platform, "supported": supported})

    def test_a_person_reads_the_same_answer(self):
        with redirect_stdout(io.StringIO()) as out:
            cli.main(["capabilities", "--no-stream"])
        text = out.getvalue()
        self.assertTrue(text.startswith("saw "), text)
        for feature in _printed(["capabilities", "--json"])["features"]:
            self.assertIn(feature, text)


if __name__ == "__main__":
    unittest.main()
