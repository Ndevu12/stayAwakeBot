# Releasing StayAwakeBot

StayAwakeBot is published as the PyPI distribution **`stayawakebot`** (the import package stays
`stayawake`). A release is cut by pushing a `v*` git tag; `.github/workflows/release.yml` then
builds the artifacts, re-scans the release commit for worm indicators, and publishes to every
channel below. There is **no `PYPI_API_TOKEN`** — PyPI upload uses Trusted Publishing (OIDC),
by design.

## Distribution channels

The bot is live on four channels, all fed by the single tag-triggered pipeline:

| Channel | Where | Published by |
|---|---|---|
| **PyPI package** | [`stayawakebot`](https://pypi.org/project/stayawakebot/) · `pip install stayawakebot` | `publish-pypi` — OIDC Trusted Publishing + PEP 740 attestations |
| **Container image** | [`ghcr.io/ndevu12/stayawakebot`](https://github.com/Ndevu12/stayAwakeBot/pkgs/container/stayawakebot) · `:X.Y.Z`, `:X.Y`, `:latest`, `:sha-<commit>` | `docker` — SLSA provenance + SBOM, Trivy-gated |
| **GitHub Release** | [Releases](https://github.com/Ndevu12/stayAwakeBot/releases) · sdist + wheel + SBOM | `github-release` — auto-generated notes |
| **GitHub Action** | [`Ndevu12/strix`](https://github.com/Ndevu12/strix) · `uses: Ndevu12/strix@v1` | thin wrapper that installs the published PyPI scanner |

Everything below is the runbook for cutting the next release and the reference for how each
channel is wired — the pipeline and its credentials are already provisioned and shipping.

## Cutting a release

1. **Finalize `CHANGELOG.md`:** rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a fresh
   empty `## [Unreleased]` above it, and add the `[X.Y.Z]` compare-link reference at the bottom.
   The changelog is version-partitioned — keep it that way; don't let entries pile up under
   `[Unreleased]` across releases.
2. **(Optional) TestPyPI dry-run:** Actions → **Release** → *Run workflow* (fires
   `workflow_dispatch` → `publish-testpypi`), then verify in a clean venv:
   ```bash
   python3 -m venv /tmp/v && . /tmp/v/bin/activate   # any supported interpreter (>=3.11)
   # TestPyPI lacks our deps, so allow PyPI as a fallback index:
   pip install --index-url https://test.pypi.org/simple/ \
               --extra-index-url https://pypi.org/simple/ stayawakebot
   saw scan --help
   ```
3. **Tag and push** — this is the entire trigger:
   ```bash
   git tag -s vX.Y.Z          # MUST be vX.Y.Z — a malformed tag yields a dev/local version
   git push origin vX.Y.Z     # hatch-vcs derives the package version from this tag
   ```
4. **Approve the `pypi` environment deployment** when the run pauses for it — the one manual gate.
5. The pipeline publishes the PyPI package (PEP 740 attestations), the GHCR image, and the GitHub
   Release (sdist + wheel + SBOM) — see **Distribution channels** above.

## Verifying a published release

- The PyPI project page shows the version and a **Provenance / attestations** panel.
- Clean-room install:
  ```bash
  pip install stayawakebot==<version>
  saw scan --help
  ```
- `pip download stayawakebot==<version>`, then `twine check` the artifacts.
- Container: `docker run --rm ghcr.io/ndevu12/stayawakebot:<version> saw scan --help`, and
  `docker buildx imagetools inspect ghcr.io/ndevu12/stayawakebot:<version>` to see provenance/SBOM.

## How publishing is configured (reference)

Recorded for audit and re-provisioning — this setup is already in place; it is **not** repeated per
release.

### GitHub Environments
Two environments gate the publish jobs:
- **`pypi`** — the protected environment for `publish-pypi`. A publish pauses here for an explicit
  approval; this is the gate that stops a compromised push from silently shipping. (Keep required
  reviewers / a deployment-tag rule enabled on it.)
- **`testpypi`** — used by the `publish-testpypi` dry-run.

### Trusted Publishers (no stored token)
PyPI and TestPyPI are separate registries; each has a Trusted Publisher bound to this workflow:
- Project **`stayawakebot`** · Owner **`Ndevu12`** · Repository **`stayAwakeBot`** · Workflow
  **`release.yml`** · Environment **`pypi`** (TestPyPI: identical, Environment **`testpypi`**).
- The four values (owner / repo / workflow / environment) must match the workflow exactly, or the
  OIDC exchange is rejected — keep them in sync if the workflow filename or environment ever changes.

### Account hardening
- 2FA is enabled on the PyPI and TestPyPI accounts.
- Keep a second project owner as a backup.

## The GitHub Action channel (Strix)

The scanner is also distributed as a GitHub Action from its own repository,
[`Ndevu12/strix`](https://github.com/Ndevu12/strix) ("StayAwakeBot Strix"). Strix is a thin
composite Action whose `action.yml` installs the published `stayawakebot` scanner from PyPI and
runs `saw scan` (gating on its exit code) — the detection engine stays in the package. This repo
carries no root `action.yml`; the in-repo `.github/actions/worm-scan` composite is kept only for
this project's own self-gating (`worm-guard.yml`) and from-source pins. (Marketplace requires the
metadata at the repo root, which is why the public Action is a separate repo, not a subpath here.)

**Tag convention (in `Ndevu12/strix`):** consumers use a moving major tag,
`uses: Ndevu12/strix@v1`. After each `vX.Y.Z` Strix release, fast-forward the major:
```bash
git tag -f v1 vX.Y.Z && git push -f origin v1
```
Strix versions independently of the `stayawakebot` package (separate repo, separate tags), so there
is no collision with the package's `hatch-vcs` tags. Keep recommending **SHA pins** (`@<sha>`) for
production consumers; the moving `v1` is convenience, not tamper-evidence.

**Scanner coupling:** Strix installs the scanner from PyPI via its `version` input (blank = latest;
pin in production). Bump that pin in lockstep with the moving `v1` so the Action references a known,
attested release. (`stayawakebot` needs Python `>=3.11`, so Strix only sets up a `>=3.11`
interpreter.)

**Marketplace listing** (one-time per Strix repo): in `Ndevu12/strix` → Releases → edit the release
→ tick *Publish this Action to the GitHub Marketplace*, accept the agreement, and pick the
**Security / Continuous integration** categories.

## The container channel (GHCR)

The `docker` job builds and pushes `ghcr.io/ndevu12/stayawakebot` on every `v*` tag. It needs no
extra secret — it authenticates to GHCR with the built-in `GITHUB_TOKEN` (`packages: write`) — and
is gated by the same worm self-scan as the package. The package is **public** and linked to this
repository, so `docker pull` needs no auth.

Each release publishes `:X.Y.Z`, `:X.Y`, `:latest`, and `:sha-<commit>`, with SLSA provenance and
an SBOM attached as attestations. A **Trivy gate** scans the image *before* publishing and fails the
job on a fixable critical/high (`ignore-unfixed: true`), so a vulnerable image never reaches GHCR —
when that fires, bump the SHA-pinned base digest in the `Dockerfile` (don't weaken the gate). The
image is built from the same wheel as PyPI, hermetically: `hatch-vcs` can't see git inside the
build, so the job passes the tag version via `--build-arg VERSION` → `SETUPTOOLS_SCM_PRETEND_VERSION`
(the generic var; the `_FOR_<dist>` named variant is ignored by hatch-vcs's backend).

## Notes & invariants

- **Versioning:** `hatch-vcs` derives the version from the tag — never hand-edit a version. A clean
  checkout at `vX.Y.Z` builds `X.Y.Z`; a dirty/untagged tree builds a `.devN+g…` version (expected,
  and not publishable to a real index).
- **sdist contents** are an allowlist (`pyproject.toml` → `tool.hatch.build.targets.sdist`): `src/`,
  README, LICENSE, CHANGELOG only. `reports/` and `tests/` fixtures (which quote malware payloads)
  are deliberately excluded — don't loosen this.
- **Re-publishing a version is impossible** — PyPI rejects duplicate uploads and GitHub Releases are
  immutable (asset re-upload 422s). Ship a fix as a new tag.

## Hardening backlog

Shipped, and now part of the pipeline: the CycloneDX **SBOM** attached to each Release; the
**`pip-audit`** release gate on the resolved dependency set (to ship past an advisory with no fix
yet, add a scoped `--ignore-vuln GHSA-xxxx` to the *Audit dependencies* step — don't drop
`--strict`); and the **GHCR container channel** with provenance/SBOM attestations and the Trivy gate.

Still open — additive, not yet wired:
- [ ] **cosign-signed release assets** beyond the PyPI/image attestations, if/when standalone
      binaries land.
- [ ] Periodic re-confirmation that **required reviewers** stay enabled on the `pypi` environment.
