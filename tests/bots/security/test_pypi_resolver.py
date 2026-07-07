#!/usr/bin/env python3
"""PyPI resolver (#1122) — requirements.txt / poetry.lock / Pipfile.lock / uv.lock → PURLs, plus
the end-to-end malware path (seed and corpus) reaching INFECTED via the frozen interface."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import AdvisoryStore, db
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.bots.security.dependencies.resolvers import PyPiResolver
from stayawake.bots.security.models import CLEAN, INFECTED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.bots.security._osv_fixtures import mal_record, osv_zip

SEED_SIG = {"id": "malicious-dependency", "category": "supply-chain-dep", "severity": "critical",
            "matcher": "dependency-audit", "description": "malware", "remediation": "manual",
            "known_bad": ["evil-pypi-pkg@6.6.6"]}
CORPUS_SIG = {**SEED_SIG, "known_bad": [], "corpus": True}


def _dir(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(content, encoding="utf-8")
    return d


def _resolve(files):
    return list(PyPiResolver().resolve(LocalRepoTarget(_dir(files), "t", ScanOptions())))


class TestRequirementsTxt(unittest.TestCase):
    def test_exact_pin(self):
        deps = _resolve({"requirements.txt": "requests==2.28.1\n"})
        self.assertEqual(deps[0].purl, Purl("pypi", "requests", "2.28.1"))
        self.assertEqual(deps[0].source_path, "requirements.txt")

    def test_name_is_pep503_normalized(self):
        deps = _resolve({"requirements.txt": "Flask_Foo.Bar==1.0\n"})
        self.assertEqual(deps[0].purl.name, "flask-foo-bar")

    def test_ranges_and_unpinned_and_options_are_skipped(self):
        req = ("# a comment\n"
               "ranged>=1.0\n"                 # range → defer to lock
               "compound==1.0,<2.0\n"          # compound spec → not an exact pin
               "unpinned\n"
               "-r other.txt\n"
               "-e .\n"
               "--hash=sha256:abc\n")
        self.assertEqual(_resolve({"requirements.txt": req}), [])

    def test_extras_markers_and_hashes_still_pin(self):
        req = ('uvicorn[standard]==0.23.2 ; python_version >= "3.8"  # comment\n'
               "certifi == 2024.2.2 --hash=sha256:deadbeef\n")
        got = {(d.purl.name, d.purl.version) for d in _resolve({"requirements.txt": req})}
        self.assertEqual(got, {("uvicorn", "0.23.2"), ("certifi", "2024.2.2")})

    def test_variant_filename_is_read(self):
        deps = _resolve({"requirements-dev.txt": "pytest==7.4.0\n"})
        self.assertEqual(deps[0].purl, Purl("pypi", "pytest", "7.4.0"))


class TestLockfiles(unittest.TestCase):
    def test_poetry_lock(self):
        lock = ('[[package]]\nname = "requests"\nversion = "2.28.1"\n\n'
                '[[package]]\nname = "urllib3"\nversion = "1.26.12"\n')
        got = {(d.purl.name, d.purl.version) for d in _resolve({"poetry.lock": lock})}
        self.assertEqual(got, {("requests", "2.28.1"), ("urllib3", "1.26.12")})

    def test_uv_lock(self):
        lock = 'version = 1\n\n[[package]]\nname = "certifi"\nversion = "2024.2.2"\n'
        deps = _resolve({"uv.lock": lock})
        self.assertEqual(deps[0].purl, Purl("pypi", "certifi", "2024.2.2"))

    def test_pipfile_lock(self):
        lock = json.dumps({"default": {"requests": {"version": "==2.28.1"}},
                           "develop": {"pytest": {"version": "==7.1.3"}}})
        got = {(d.purl.name, d.purl.version) for d in _resolve({"Pipfile.lock": lock})}
        self.assertEqual(got, {("requests", "2.28.1"), ("pytest", "7.1.3")})

    def test_ecosystem_is_pypi(self):
        for d in _resolve({"poetry.lock": '[[package]]\nname = "x"\nversion = "1.0"\n'}):
            self.assertEqual(d.purl.type, "pypi")

    def test_malformed_files_do_not_crash(self):
        self.assertEqual(_resolve({"poetry.lock": "not [[ valid toml",
                                   "Pipfile.lock": "{ not json"}), [])


class TestPyPiEndToEnd(unittest.TestCase):
    def test_seed_hit_via_requirements_is_infected(self):
        # `evil_pypi.pkg` normalizes to the seed coordinate `evil-pypi-pkg` → INFECTED.
        d = _dir({"requirements.txt": "evil_pypi.pkg==6.6.6\n"})
        r = scan_target(LocalRepoTarget(d, "t", ScanOptions()), {"dependency-audit": [SEED_SIG]}, [])
        self.assertEqual(r.verdict, INFECTED)
        self.assertEqual([f.signature_id for f in r.findings], ["malicious-dependency"])

    def test_clean_requirements_is_clean(self):
        d = _dir({"requirements.txt": "requests==2.28.1\n"})
        r = scan_target(LocalRepoTarget(d, "t", ScanOptions()), {"dependency-audit": [SEED_SIG]}, [])
        self.assertEqual(r.verdict, CLEAN)

    def test_corpus_pypi_record_matches_case_insensitively(self):
        cache = Path(tempfile.mkdtemp())
        db._CORPUS_MEMO.clear()
        # OSV writes the ecosystem as "PyPI"; a "pypi" PURL must still match.
        z = osv_zip({"MAL.json": mal_record("evil-lib", ["9.9.9"], rid="MAL-2024-5", ecosystem="PyPI")})
        db.write_manifest(cache, [db.update_ecosystem("pypi", cache, fetch=lambda b: z)])
        store = AdvisoryStore.default([CORPUS_SIG], cache_dir=cache)
        self.assertIsNotNone(store.advisory_for(Purl("pypi", "evil-lib", "9.9.9")))
        db._CORPUS_MEMO.clear()


if __name__ == "__main__":
    unittest.main()
