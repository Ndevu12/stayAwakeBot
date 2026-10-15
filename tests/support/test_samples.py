#!/usr/bin/env python3
"""The sample payloads the tests build are the ones the tests were written against, still read as
a payload, and the files that build them hold none."""
from __future__ import annotations

import hashlib
import py_compile
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.support import samples

_INFECTED_PROJECT_SHA256 = {
    "postcss.config.mjs": "66f00fcdf2e328933edb244bc652d98d2157073382d054f375fbd19e37b08ece",
    ".gitignore": "311270e69fc5f5a21750282b49c25c99c7f215c0d6c3120265effb3577aaef52",
    "package.json": "40ea26d70237f84349d6a89eb8a66aebe48d01120d56f1c57b6b4513d96a6502",
    ".claude/settings.json": "44e7f7eb301cb92b9b2400b1f6608053b008c7b9a3c6fdda8678c14027595669",
    ".vscode/settings.json": "6fb9cb432d1bac3f12aad4c5bb1ddf39425ab44614d1698b773d6d25ee68e474",
    ".vscode/tasks.json": "64304df3e427a90d0da07af049688521998e10e9248863dc9f116b7e5c3b3e59",
    "public/fonts/fa-solid-400.woff2": "519469a4e67e786eb2b388673d67968a4646ad6bccb19e289b5d3aeafb88c8ca",
    "public/fonts/README.md": "659905db18829b79590a29ca0a97d73f2ee5160ab84a783b71b280cf89c49d6d",
}


def _files(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def _scan(root: Path):
    return scan_target(LocalRepoTarget(root, root.name, ScanOptions()), load_signatures(), [])


class TestTheInfectedProject(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="samples-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_it_is_the_project_the_tests_were_written_against(self):
        built = samples.write_infected_project(self.root / "infected")
        self.assertEqual(_files(built), sorted(_INFECTED_PROJECT_SHA256))
        for relative, digest in _INFECTED_PROJECT_SHA256.items():
            with self.subTest(file=relative):
                self.assertEqual(hashlib.sha256((built / relative).read_bytes()).hexdigest(), digest)

    def test_it_reads_infected(self):
        self.assertTrue(_scan(samples.write_infected_project(self.root / "infected")).infected)

    def test_the_fixtures_folder_holds_both_projects(self):
        folder = samples.write_fixtures(self.root / "fixtures")
        self.assertEqual(_files(folder / "clean"), _files(samples.CLEAN_PROJECT))
        self.assertTrue(_files(folder / "clean"))
        self.assertFalse(_scan(folder / "clean").findings)
        self.assertTrue(_scan(folder / "infected").infected)


class TestEachPieceReadsAsWhatItIsNamedFor(unittest.TestCase):
    def test_each_piece_reads_as_its_signature(self):
        pieces = {
            "loader-decoder-fn": f"x = {samples.DECODER}(0);\n",
            "loader-seed-var": f"var {samples.seed()} = 1;\n",
            "loader-global-bang": f"{samples.GLOBAL}['!'] = 1;\n",
            "loader-global-v-marker": samples.marked_loader(),
            "loader-fromcharcode-127": f"const s=String.{samples.FROM_CHAR_CODE}(127);eval(s);\n",
            "loader-clientcode-error": f"console.log('{samples.CLIENT_CODE_ERROR}: boom');\n",
        }
        for signature_id, text in pieces.items():
            with self.subTest(signature=signature_id):
                root = Path(tempfile.mkdtemp(prefix="piece-"))
                self.addCleanup(shutil.rmtree, root, True)
                (root / "index.js").write_text(text, encoding="utf-8")
                self.assertIn(signature_id, {f.signature_id for f in _scan(root).findings})


class TestTheFilesThatBuildThemHoldNone(unittest.TestCase):
    def test_no_signature_matches_them_or_what_python_compiles_from_them(self):
        root = Path(tempfile.mkdtemp(prefix="samples-source-"))
        self.addCleanup(shutil.rmtree, root, True)
        support = root / "tests" / "support"
        support.mkdir(parents=True)
        here = Path(__file__).resolve().parent
        for name in ("samples.py", "test_samples.py"):
            shutil.copy2(here / name, support / name)
            compiled = support / "__pycache__" / f"{Path(name).stem}.{sys.implementation.cache_tag}.pyc"
            py_compile.compile(str(support / name), cfile=str(compiled), doraise=True)
        self.assertTrue(list((support / "__pycache__").glob("samples.*.pyc")))
        self.assertEqual([(f.signature_id, f.path) for f in _scan(root).findings], [])


if __name__ == "__main__":
    unittest.main()
