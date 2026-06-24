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
   python3.14 -m venv /tmp/v && . /tmp/v/bin/activate
   # TestPyPI lacks our deps, so allow PyPI as a fallback index:
   pip install --index-url https://test.pypi.org/simple/ \
               --extra-index-url https://pypi.org/simple/ stayawakebot
   stayawake-security-scan --help
   ```
3. Tag and push:
   ```bash
   git tag v0.1.0          # version is derived from this tag by hatch-vcs
   git push origin v0.1.0
   ```
4. Approve the `pypi` environment deployment when prompted.
5. The workflow publishes to PyPI (with PEP 740 attestations) and creates the GitHub Release
   with the sdist + wheel attached.

## Verifying a published release

- PyPI project page shows the version and a **"Provenance / attestations"** panel.
- Clean-room install:
  ```bash
  pip install stayawakebot==<version>
  stayawake-security-scan --help
  ```
- `pip download stayawakebot==<version>` then `twine check` the artifacts.

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

- [ ] **SBOM** (CycloneDX via `cyclonedx-py`) generated in the build job and attached to the
      GitHub Release.
- [ ] **`pip-audit`** as a release gate on the dependency set.
- [ ] **Standalone signature/sigstore step** beyond the PyPI attestations (e.g. cosign-signed
      release assets) if we add non-PyPI channels (Docker/binaries — P3/P4).
- [ ] **Required reviewers** actually enabled on the `pypi` environment (manual, step 1).
