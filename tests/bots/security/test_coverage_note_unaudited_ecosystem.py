#!/usr/bin/env python3
"""A project whose dependencies could not be resolved to audit is named in the scan's notes."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import AdvisoryStore
from stayawake.bots.security.dependencies.markers import unaudited_ecosystems
from stayawake.bots.security.dependencies.resolvers import RESOLVERS
from stayawake.bots.security.matchers.dependency_audit import DependencyAuditMatcher
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

_SIG = {"known_bad": ["some-malicious-pkg@1.0.0"]}          # makes the advisory store non-empty


def _notes(files: dict) -> list[str]:
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(content, encoding="utf-8")
    target = LocalRepoTarget(d, "t", ScanOptions())
    matcher = DependencyAuditMatcher(store_factory=lambda sigs: AdvisoryStore.from_signatures(sigs))
    matcher.scan(target, [_SIG])
    return target.coverage_notes


class TestDetection(unittest.TestCase):
    def test_a_first_party_manifest_with_no_resolved_dep_is_named(self):
        self.assertEqual(unaudited_ecosystems(["Cargo.toml"], set(), RESOLVERS), {"cargo": "Rust"})

    def test_a_resolved_ecosystem_is_not_named(self):
        self.assertEqual(unaudited_ecosystems(["Cargo.toml"], {"cargo"}, RESOLVERS), {})

    def test_a_vendored_manifest_is_not_named(self):
        self.assertEqual(unaudited_ecosystems(["third_party/esbuild/package.json"], set(), RESOLVERS), {})
        self.assertEqual(unaudited_ecosystems(["vendor/x/Cargo.toml"], set(), RESOLVERS), {})

    def test_a_nested_first_party_manifest_is_named(self):
        self.assertEqual(unaudited_ecosystems(["src/App/App.csproj"], set(), RESOLVERS), {"nuget": ".NET"})

    def test_a_flutter_project_is_named(self):
        self.assertEqual(unaudited_ecosystems(["pubspec.yaml"], set(), RESOLVERS), {"pub": "Dart/Flutter"})


class TestUnauditedNote(unittest.TestCase):
    def test_a_rust_project_without_a_lockfile_is_named(self):
        notes = _notes({"Cargo.toml": "[package]\nname = 'a'\n", "src/main.rs": "fn main(){}\n"})
        self.assertTrue(any("Rust" in n and "lockfile" in n for n in notes), notes)

    def test_a_resolvable_lockfile_produces_no_note(self):
        lock = ("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n\n"
                "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n")
        notes = _notes({"Gemfile": "source 'x'\n", "Gemfile.lock": lock})
        self.assertFalse(any("Ruby" in n for n in notes), notes)

    def test_a_vendored_dependency_manifest_does_not_fire(self):
        notes = _notes({"go.mod": "module x\ngo 1.21\n", "third_party/esbuild/package.json": '{"name":"esbuild"}'})
        self.assertFalse(any("npm" in n for n in notes), notes)
