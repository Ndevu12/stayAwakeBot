---
description: Check that a saw release file was built by saw's release pipeline from its signed tag, and install a wheel with every dependency pinned by hash.
---

# Verify a release

Every saw release on GitHub carries, next to the sdist and the wheels:

| File | What it is |
| --- | --- |
| `stayawakebot-<version>.provenance.sigstore.json` | The signed build provenance for every file below |
| `SHA256SUMS` | The SHA-256 of every file in the release |
| `stayawakebot-<version>.platforms.json` | For each system and architecture: its wheel, the wheel's SHA-256, and the oldest glibc or macOS it runs on |
| `stayawakebot-<version>.requirements.lock` | saw and each of its dependencies, pinned by hash, for every platform and Python saw supports |
| `stayawakebot-<version>.sbom.cdx.json` | The software bill of materials |

The provenance is signed with a certificate issued to saw's release workflow for that one run, and
the signature is recorded in Sigstore's public transparency log. No signing key is stored anywhere.

## Check a file

```text
gh attestation verify <file> \
  --bundle stayawakebot-<version>.provenance.sigstore.json \
  --repo Ndevu12/stayAwakeBot \
  --signer-workflow Ndevu12/stayAwakeBot/.github/workflows/release.yml \
  --source-ref refs/tags/v<version> \
  --deny-self-hosted-runners
```

It passes only for a file built by saw's release workflow from the tag `v<version>` on a
GitHub-hosted runner. Check each file you install: the wheel, the lock and the manifest.

## Install with every dependency pinned

Pick your wheel from `stayawakebot-<version>.platforms.json`, put it in a folder with the lock, and
install from that folder:

```text
python3 -m venv saw-env
saw-env/bin/pip install --only-binary=:all: --require-hashes --no-deps \
  --find-links . -r stayawakebot-<version>.requirements.lock
```

pip installs nothing whose hash the lock does not name.
