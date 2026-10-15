#!/usr/bin/env python3
"""A git hook whose text carries the decoy README's phrase is not a payload; a hook that carries a loader, the
worm's own file names or its runner, or writes a runner registration, still is, and the decoy README in its own
file is still found."""
from __future__ import annotations

import unittest

from stayawake.bots.security.matchers.git_exec_surface import PAYLOAD_SIGNATURE
from stayawake.bots.security.models import CONFIRMED
from tests.bots.security.test_git_exec_surface import LOADER, ExecSurfaceSandbox
from tests.support import samples

DECOY = samples.joined("Blockchain Ex", "plorer")
PUSH_TOOL = samples.joined("temp_auto", "_push.bat")
REGISTRATION = samples.joined('{"server', 'Url": "https://ci.example.invalid"}')


class _Hooks(ExecSurfaceSandbox):
    def hooked(self, body: str):
        repo = self.repo()
        self.hook(repo / ".git" / "hooks", "pre-commit", "#!/bin/sh\n" + body)
        return repo

    def payloads(self, repo) -> list:
        return [f for f in self.scan(repo).findings
                if f.signature_id == PAYLOAD_SIGNATURE and f.confidence == CONFIRMED]


class TestADecoyPhraseInAHookIsNotAPayload(_Hooks):
    def test_a_hook_that_echoes_the_phrase_is_not_a_payload(self):
        repo = self.hooked(f'echo "{DECOY}: linting staged files"; npm run lint\n')
        self.assertEqual(self.payloads(repo), [])


class TestAHookThatCarriesAPayloadIsStillOne(_Hooks):
    def test_the_phrase_beside_a_loader_is_a_payload(self):
        self.assertEqual(len(self.payloads(self.hooked(f'echo "{DECOY}"\nnode -e "{LOADER.strip()}"\n'))), 1)

    def test_a_loader_is_a_payload(self):
        self.assertEqual(len(self.payloads(self.hooked(f'node -e "{LOADER.strip()}"\n'))), 1)

    def test_the_worms_push_tool_is_a_payload(self):
        self.assertEqual(len(self.payloads(self.hooked(f"cmd /c {PUSH_TOOL}\n"))), 1)

    def test_the_worms_runner_is_a_payload(self):
        self.assertEqual(len(self.payloads(self.hooked(f"./config.sh --name {samples.RUNNER_NAME}\n"))), 1)

    def test_a_hook_that_writes_a_runner_registration_is_a_payload(self):
        self.assertEqual(len(self.payloads(self.hooked(f"echo '{REGISTRATION}' > .runner\n"))), 1)


class TestTheDecoyReadmeInItsOwnFileIsStillFound(_Hooks):
    def test_the_readme_beside_the_fonts_is_found(self):
        repo = self.repo()
        self.write(repo, "public/fonts/README.md", f"# {DECOY} fonts\n")
        self.commit(repo, "fonts")
        found = {f.signature_id for f in self.scan(repo).findings}
        self.assertIn("camouflage-blockchain-readme", found)


if __name__ == "__main__":
    unittest.main()
