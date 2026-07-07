#!/usr/bin/env python3
"""Ecosystem resolvers (#1123): Cargo / Go / RubyGems / Composer / NuGet / Maven parsing +
version normalization, and the OSV-name ↔ PURL-type canonicalization that lets a resolver's
`Purl` match an advisory record."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies.corpus import AdvisoryCorpus
from stayawake.bots.security.dependencies.osv import OsvAffected, OsvRecord
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.bots.security.dependencies.resolvers import (
    CargoResolver, ComposerResolver, GoResolver, MavenResolver, NuGetResolver, RubyGemsResolver)
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions


def _resolve(resolver, files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(content, encoding="utf-8")
    return {(x.purl.type, x.purl.name, x.purl.version)
            for x in resolver.resolve(LocalRepoTarget(d, "t", ScanOptions()))}


class TestCargo(unittest.TestCase):
    def test_cargo_lock(self):
        lock = '[[package]]\nname = "serde"\nversion = "1.0.190"\n'
        self.assertEqual(_resolve(CargoResolver(), {"Cargo.lock": lock}),
                         {("cargo", "serde", "1.0.190")})


class TestGo(unittest.TestCase):
    def test_go_sum_strips_v_and_gomod_suffix(self):
        gosum = ("github.com/foo/bar v1.2.3 h1:AAA=\n"
                 "github.com/foo/bar v1.2.3/go.mod h1:BBB=\n")
        self.assertEqual(_resolve(GoResolver(), {"go.sum": gosum}),
                         {("golang", "github.com/foo/bar", "1.2.3")})

    def test_go_mod_require_block_and_major_version_path(self):
        gomod = ("module example.com/x\n\ngo 1.21\n\nrequire (\n"
                 "    github.com/foo/bar/v2 v2.1.0 // indirect\n"
                 "    golang.org/x/net v0.17.0\n)\n")
        self.assertEqual(_resolve(GoResolver(), {"go.mod": gomod}),
                         {("golang", "github.com/foo/bar/v2", "2.1.0"),
                          ("golang", "golang.org/x/net", "0.17.0")})


class TestRubyGems(unittest.TestCase):
    def test_resolved_specs_only_and_platform_stripped(self):
        lock = ("GEM\n  remote: https://rubygems.org/\n  specs:\n"
                "    rails (7.0.4)\n"
                "    nokogiri (1.13.6-x86_64-linux)\n"
                "      racc (~> 1.4)\n"                       # 6-space constraint → skip
                "\nPLATFORMS\n  ruby\n")
        self.assertEqual(_resolve(RubyGemsResolver(), {"Gemfile.lock": lock}),
                         {("gem", "rails", "7.0.4"), ("gem", "nokogiri", "1.13.6")})


class TestComposer(unittest.TestCase):
    def test_packages_and_dev_with_v_prefix(self):
        lock = json.dumps({"packages": [{"name": "monolog/monolog", "version": "v2.9.1"}],
                           "packages-dev": [{"name": "phpunit/phpunit", "version": "9.6.3"}]})
        self.assertEqual(_resolve(ComposerResolver(), {"composer.lock": lock}),
                         {("composer", "monolog/monolog", "2.9.1"),
                          ("composer", "phpunit/phpunit", "9.6.3")})


class TestNuGet(unittest.TestCase):
    def test_resolved_versions_across_frameworks(self):
        lock = json.dumps({"version": 1, "dependencies": {
            "net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}}}})
        self.assertEqual(_resolve(NuGetResolver(), {"packages.lock.json": lock}),
                         {("nuget", "Newtonsoft.Json", "13.0.1")})


class TestMaven(unittest.TestCase):
    def test_gradle_lockfile(self):
        lock = "com.google.guava:guava:31.0.1-jre=compileClasspath\nempty=\n"
        self.assertEqual(_resolve(MavenResolver(), {"gradle.lockfile": lock}),
                         {("maven", "com.google.guava:guava", "31.0.1-jre")})

    def test_pom_literal_versions_only(self):
        pom = ('<project><dependencies>'
               '<dependency><groupId>org.springframework</groupId>'
               '<artifactId>spring-core</artifactId><version>5.3.20</version></dependency>'
               '<dependency><groupId>a</groupId><artifactId>b</artifactId>'
               '<version>${b.version}</version></dependency>'          # property → skip
               '<dependency><groupId>c</groupId><artifactId>d</artifactId>'
               '<version>[1.0,2.0)</version></dependency>'             # range → skip
               '</dependencies></project>')
        self.assertEqual(_resolve(MavenResolver(), {"pom.xml": pom}),
                         {("maven", "org.springframework:spring-core", "5.3.20")})

    def test_malformed_pom_does_not_crash(self):
        self.assertEqual(_resolve(MavenResolver(), {"pom.xml": "<project><oops"}), set())


class TestEcosystemCanonicalization(unittest.TestCase):
    def test_osv_ecosystem_names_map_to_purl_types(self):
        # Advisory records use OSV names (crates.io/Go/RubyGems/Packagist); resolvers emit PURL
        # types (cargo/golang/gem/composer). They must still match.
        cases = [("crates.io", "cargo"), ("Go", "golang"),
                 ("RubyGems", "gem"), ("Packagist", "composer")]
        for osv_name, purl_type in cases:
            corpus = AdvisoryCorpus.from_records([OsvRecord(
                id="MAL-x", aliases=(), malicious=True,
                affected=(OsvAffected(osv_name, "evil", frozenset({"6.6.6"})),))])
            self.assertIsNotNone(corpus.malicious_match(Purl(purl_type, "evil", "6.6.6")),
                                 f"{osv_name} record must match a {purl_type} PURL")


if __name__ == "__main__":
    unittest.main()
