# Releasing StayAwakeBot

This project ships as the PyPI distribution **`stayawakebot`** (the import package stays
`stayawake`). Releases are cut by pushing a `v*` git tag; `.github/workflows/release.yml`
then builds, self-scans, publishes to PyPI via **Trusted Publishing (OIDC)**, and creates a
GitHub Release. There is **no `PYPI_API_TOKEN`** — by design.

## Activate the workflow (one-time, required first)

The release workflow lives at **`.github/workflows-staged/release.yml`** instead of
`.github/workflows/release.yml`. It was staged there because the automation credential that
opened this branch lacks the GitHub `workflow` scope and cannot write under
`.github/workflows/`. Activate it with a credential that has that scope (i.e. your own
`git`):

```bash
git mv .github/workflows-staged/release.yml .github/workflows/release.yml
git commit -m "ci(release): activate release pipeline"
git push
```

(`git mv` keeps the staged directory out of the tree; nothing else needs to change.)

## One-time setup (manual — do this before the first release)

These steps happen on the PyPI/GitHub web UIs and cannot be automated from the repo.

### 1. Create the GitHub Environments
Repo → Settings → Environments → create two environments:
- **`pypi`** — used by the `publish-pypi` job.
- **`testpypi`** — used by the `publish-testpypi` dry-run job.

Add required reviewers / a deployment branch-or-tag rule to the `pypi` environment so a
publish cannot happen without an explicit approval. This is the protected gate that stops a
compromised push from silently shipping a release.

### 2. Configure Trusted Publishers (Pending Publisher — before the project exists)
PyPI and TestPyPI are **separate** registries; configure each.

- **PyPI:** https://pypi.org/manage/account/publishing/ → *Add a pending publisher*:
  - PyPI Project Name: `stayawakebot`
  - Owner: `Ndevu12`
  - Repository name: `stayAwakeBot`
  - Workflow filename: `release.yml`
  - Environment name: `pypi`
- **TestPyPI:** https://test.pypi.org/manage/account/publishing/ → same values, but
  Environment name: `testpypi`.

The four values (owner / repo / workflow / environment) must match the workflow exactly or
the OIDC exchange is rejected.

### 3. Account hardening
- Enable 2FA on the PyPI **and** TestPyPI accounts.
- Add a second project owner as a backup once the project exists.

## Cutting a release

1. Update `CHANGELOG.md`: move items from `[Unreleased]` into a new version section.
2. (Optional but recommended) Dry-run to TestPyPI: Actions → **Release** → *Run workflow*
   (this triggers `workflow_dispatch` → `publish-testpypi`). Then verify in a clean venv:
   ```bash
   python3 -m venv /tmp/v && . /tmp/v/bin/activate   # any supported interpreter (>=3.11)
   # TestPyPI lacks our deps, so allow PyPI as a fallback index:
   pip install --index-url https://test.pypi.org/simple/ \
               --extra-index-url https://pypi.org/simple/ stayawakebot
   saw scan --help
   ```
3. Tag and push:
   ```bash
   git tag v0.1.0          # MUST be vX.Y.Z (a malformed tag like v.1.4 yields a dev/local
   git push origin v0.1.0  # version PyPI rejects); hatch-vcs derives the version from this tag
   ```
4. Approve the `pypi` environment deployment when prompted.
5. The workflow publishes to PyPI (with PEP 740 attestations) and creates the GitHub Release
   with the sdist + wheel attached.

## Verifying a published release

- PyPI project page shows the version and a **"Provenance / attestations"** panel.
- Clean-room install:
  ```bash
  pip install stayawakebot==<version>
  saw scan --help
  ```
- `pip download stayawakebot==<version>` then `twine check` the artifacts.

## Publishing the Action to the Marketplace (P2)

The scanner is also a GitHub Action, and it now lives in **its own repository,
[`Ndevu12/strix`](https://github.com/Ndevu12/strix)** ("StayAwakeBot Strix" on the Marketplace).
Strix is a thin composite Action whose `action.yml` installs the published `stayawakebot` scanner
from PyPI and runs `saw scan` (gating on its exit code) — the detection engine stays in the
package. This
repo no longer carries a root `action.yml`; the in-repo `.github/actions/worm-scan` composite is
kept only for this project's own self-gating (`worm-guard.yml`) and from-source pins. Marketplace
requires the metadata at the repo root, which is why the public Action is a separate repo rather
than a subpath here.

### One-time listing (in `Ndevu12/strix`)
1. The root `action.yml` already has a unique `name` (`StayAwakeBot Strix`), a `description`, and
   `branding` (icon + color). Marketplace action names are globally unique; adjust the `name`
   field if it is ever taken.
2. GitHub → **`Ndevu12/strix`** → **Releases → edit the `v0.1.0` release** → tick **"Publish this
   Action to the GitHub Marketplace"**, accept the agreement, and pick a primary + secondary
   category (**Security / Continuous integration**).
3. Save the release.

### Tag convention (in `Ndevu12/strix`)
- **Action (Marketplace):** consumers expect a **moving major** tag, `uses: Ndevu12/strix@v1`.
  After each `vX.Y.Z` release of Strix, fast-forward the major tag:
  ```bash
  git tag -f v1 vX.Y.Z      # move v1 to the new release
  git push -f origin v1
  ```
- Strix versions independently of the `stayawakebot` package (separate repo, separate tags), so
  there is no namespace collision with the package's `hatch-vcs` `vX.Y.Z` tags here.
- Keep recommending **SHA pins** (`@<sha>`) in docs for production consumers; the moving `v1`
  is for convenience, not for tamper-evidence.

### Scanner-version coupling
Strix installs the scanner from PyPI via its `version` input (blank = latest; pin in production).
Bump that pin in lockstep with the moving `v1` tag so the published Action references a known,
attested release. Note: `stayawakebot` requires Python `>=3.11`, so Strix's `action.yml` only
needs to set up a `>=3.11` interpreter to run the scanner (a newer minor such as 3.14 is fine).

## Container image (GHCR — P3)

The release workflow's `docker` job also builds and pushes a container to
`ghcr.io/ndevu12/stayawakebot` on every `v*` tag. It needs **no extra secret** — it
authenticates to GHCR with the built-in `GITHUB_TOKEN` (`packages: write`) — and is gated by
the same worm self-scan as the package.

One-time, after the first image is pushed:
- Repo → **Packages** → `stayawakebot` → **Package settings**: set visibility to **Public**
  (so `docker pull` needs no auth) and **link it to this repository**.

Each release publishes `:X.Y.Z`, `:X.Y`, `:latest`, and `:sha-<commit>`, with SLSA provenance
and an SBOM attached as attestations, plus a Trivy SARIF scan (report-only — base-image CVEs
don't block a release; the SARIF is the audit record). The image is built from the same wheel
as PyPI, hermetically: `hatch-vcs` can't see git inside the build, so the job passes the tag
version via `--build-arg VERSION` → `SETUPTOOLS_SCM_PRETEND_VERSION` (the generic var; the
`_FOR_<dist>` named variant is ignored by hatch-vcs's backend).

Verify a published image:
```bash
docker run --rm ghcr.io/ndevu12/stayawakebot:<version> saw scan --help
docker buildx imagetools inspect ghcr.io/ndevu12/stayawakebot:<version>   # see provenance/SBOM
```

## Notes & invariants

- **Versioning:** `hatch-vcs` derives the version from the tag — never hand-edit a version.
  A clean checkout at tag `v0.1.0` builds `0.1.0`; a dirty/untagged tree builds a `.devN+g…`
  version (expected, and not publishable to a real index).
- **sdist contents** are an allowlist (`pyproject.toml` → `tool.hatch.build.targets.sdist`):
  `src/`, README, LICENSE, CHANGELOG only. `reports/` and `tests/` fixtures (which quote
  malware payloads) are deliberately excluded — do not loosen this.
- **Re-publishing a version is impossible** (PyPI rejects duplicates). Bump the tag.

## Remaining hardening backlog (not yet in the pipeline)

Tracked here rather than silently omitted. Each is additive to the current pipeline:

- [x] **SBOM** (CycloneDX via `cyclonedx-py`) — generated in the build job from the wheel's
      resolved deps and attached to the GitHub Release as `sbom.cdx.json`.
- [x] **`pip-audit`** — release gate on the resolved dependency set. To ship past an advisory
      that has no fix yet, add a scoped `--ignore-vuln GHSA-xxxx` to the *Audit dependencies*
      step (don't drop `--strict`).
- [x] **Container channel (P3)** — GHCR image with SLSA provenance + SBOM attestations and a
      **Trivy gate**: the image is built and scanned *before* publishing, and a fixable
      critical/high (`ignore-unfixed: true`) fails the job before anything is pushed.
- [ ] **cosign-signed release assets** beyond the PyPI/image attestations, if/when P4 binaries land.
- [ ] **Required reviewers** actually enabled on the `pypi` environment (manual, step 1).
