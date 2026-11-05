#!/usr/bin/env python3
"""A project whose dependencies could not be resolved to audit is named in the scan's notes."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import AdvisoryStore
from stayawake.bots.security.dependencies.markers import detected_ecosystems
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
    def test_markers_map_to_ecosystems(self):
        self.assertEqual(detected_ecosystems(["Cargo.toml"]), {"cargo": "Rust"})
        self.assertEqual(detected_ecosystems(["a/b/App.csproj"]), {"nuget": ".NET"})
        self.assertEqual(detected_ecosystems(["pubspec.yaml"]), {"pub": "Dart/Flutter"})
        self.assertEqual(detected_ecosystems(["README.md", "src/main.rs"]), {})


class TestUnauditedNote(unittest.TestCase):
    def test_a_rust_project_without_a_lockfile_is_named_unaudited(self):
        notes = _notes({"Cargo.toml": "[package]\nname = 'a'\n", "src/main.rs": "fn main(){}\n"})
        self.assertTrue(any("Rust" in n and "not audited" in n for n in notes), notes)

    def test_a_resolvable_lockfile_produces_no_note(self):
        lock = ("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n\n"
                "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n")
        notes = _notes({"Gemfile": "source 'x'\n", "Gemfile.lock": lock})
        self.assertFalse(any("Ruby" in n for n in notes), notes)
