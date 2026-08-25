#!/usr/bin/env python3
"""Behaviour pinned for the capability-graded loader signature and the host escalation."""
import re
import unittest

from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.sinks.render import _local_loader_paths

SIG_ID = "loader-require-escapes-esm"


def _pattern():
    for group in load_signatures(None).values():
        for s in group:
            if s.get("id") == SIG_ID:
                return re.compile(s["pattern"])
    raise AssertionError(f"{SIG_ID} not found")


class CapabilityPattern(unittest.TestCase):
    def setUp(self):
        self.rx = _pattern()

    def test_it_matches_both_packer_families(self):
        # the two spellings seen in the wild — one indexes a table, one uses a plain key
        for sample in ("global[_$_1e42[0]]= require;", "global['r']=require;"):
            with self.subTest(sample=sample):
                self.assertTrue(self.rx.search(sample))

    def test_a_computed_key_is_spanned(self):
        # a key containing its own brackets defeats a naive [^\]]+ key
        self.assertTrue(self.rx.search("global[_$_1e42[0]] = require"))

    def test_globalthis_counts(self):
        # both spellings of the global object are covered
        self.assertTrue(self.rx.search("globalThis.r = require"))

    def test_module_capture_counts_too(self):
        self.assertTrue(self.rx.search("global['m']=module"))

    def test_a_name_merely_ending_in_global_is_not_a_match(self):
        for sample in ("myglobal.x = require", "obj.global.x = require", "a_global.y = module"):
            with self.subTest(sample=sample):
                self.assertFalse(self.rx.search(sample))

    def test_ordinary_require_is_not_a_match(self):
        for sample in ("const x = require('fs')", "module.exports = require('./a')",
                       "global.foo = 3", "window.global = require"):
            with self.subTest(sample=sample):
                self.assertFalse(self.rx.search(sample))

    def test_polyfill_setup_that_assigns_module_exports_is_not_a_match(self):
        # Assigning what require RETURNS is ordinary Jest/Node setup; assigning require ITSELF hands
        # over the loader. Without this distinction 7 of these 10 matched.
        for sample in ("global.fetch = require('node-fetch')",
                       "global.WebSocket = require('ws');",
                       "globalThis.crypto = require('crypto').webcrypto;",
                       "global.TextEncoder = require('util').TextEncoder;",
                       "global.jsdom = require('jsdom');",
                       "global.Buffer = global.Buffer || require('buffer').Buffer;",
                       "if (!global.fetch) { global.fetch = require('cross-fetch'); }",
                       "global.expect = require('expect');",
                       "global.r = require.cache",
                       "global.foo = require\n('x')"):
            with self.subTest(sample=sample):
                self.assertFalse(self.rx.search(sample), sample)

    def test_a_same_named_interop_shim_is_not_a_match(self):
        # `global.require = require` is a bundler/Electron shim; the loader hides under another name.
        for sample in ("global.require = require;", "globalThis.module = module;",
                       "global.module = module",
                       "if (typeof global.require === 'undefined') global.require = require;"):
            with self.subTest(sample=sample):
                self.assertFalse(self.rx.search(sample), sample)

    def test_compound_assignment_is_covered(self):
        for sample in ("global['r'] ??= require;", "global.r ||= require;"):
            with self.subTest(sample=sample):
                self.assertTrue(self.rx.search(sample), sample)

    def test_the_bare_binding_is_still_caught_in_every_spelling(self):
        for sample in ("global['r']=require;", "global.r = require", "globalThis['q']=require ;",
                       "global['m']=module;", "global[_$_1e42[0]]= require;"):
            with self.subTest(sample=sample):
                self.assertTrue(self.rx.search(sample), sample)

    def test_the_pattern_does_not_match_its_own_definition(self):
        # signatures.yml is scanned like any other file; a self-match reads as an infection
        for group in load_signatures(None).values():
            for s in group:
                if s.get("id") == SIG_ID:
                    self.assertFalse(self.rx.search(s["pattern"]))


class HostEscalation(unittest.TestCase):
    """A loader in a working tree on THIS machine may already have run."""

    @staticmethod
    def _payload(source, category="code-loader", confidence="confirmed"):
        return {"results": [{"source": source, "findings": [
            {"category": category, "confidence": confidence, "path": "postcss.config.mjs"}]}]}

    def test_a_local_confirmed_loader_escalates(self):
        self.assertEqual(_local_loader_paths(self._payload("local")), ["postcss.config.mjs"])

    def test_a_remote_finding_says_nothing_about_this_host(self):
        self.assertEqual(_local_loader_paths(self._payload("remote")), [])

    def test_a_heuristic_finding_does_not_escalate(self):
        self.assertEqual(_local_loader_paths(self._payload("local", confidence="heuristic")), [])

    def test_a_non_loader_finding_does_not_escalate(self):
        self.assertEqual(_local_loader_paths(self._payload("local", category="camouflage")), [])


if __name__ == "__main__":
    unittest.main()
