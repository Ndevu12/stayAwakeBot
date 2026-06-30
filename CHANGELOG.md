# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`saw fix` — remediate on a branch; `--pr` to publish.** `saw fix` prepares the cleanup on a
  local `security/auto-clean` branch and stops (no push, no network) — review it and push when
  ready; **`--pr`** also pushes and opens/updates one rolling, de-duplicated PR per repo;
  **`--remote`** sweeps configured GitHub repos (clone → fix → PR). Cleanup is delivered as a
  branch/PR, never an in-place edit, so it can't corrupt your working tree. Each repo's outcome
  streams live (scanning → fixing → opening PR) under a `Security fix — <timestamp>` header.
- **`saw discard` — undo a fix.** Removes only the auto-generated `security/auto-clean` branch:
  **`--branch`** deletes it locally and on its remote (pure git — works even when the GitHub API
  is unreachable; deleting the remote branch auto-closes its PR), **`--pr`** closes the PR via the
  API. Local by default; `--remote` sweeps the fleet.
- **Discoverable remote targeting.** `scan`/`fix`/`discard --remote` resolve GitHub targets by a
  ladder — ad-hoc **`--user`/`--org`** and `owner/repo` selectors (which override config) →
  configured `targets.github` → **your own repos** (owned, private-inclusive via `/user/repos`) or
  a GitHub App installation. `--user`/`--org` imply `--remote`; a non-`owner/repo` positional under
  `--remote` is a hard error.
- **Large-fleet result presentation.** A report taller than the terminal is **paged** through
  `$PAGER` (`--no-pager` to opt out); **clean rows collapse to a count** in the table once the fleet
  is large (the full inventory stays in `--json`/`-d`); and a big sweep with no `-d`/`--json` writes
  the **full Markdown + JSON to a temp dir and prints its path** — so a 200-repo result is never
  lost to terminal scrollback.
- **Readable terminal report.** The interactive scan output is an aligned, colour-coded table
  (red INFECTED / yellow SUSPECT / green clean on a TTY; honours `NO_COLOR`) listing every
  scanned target, sorted worst-first. Findings are detailed per infected/suspect repo in spaced
  blocks: an underlined project header, then one bulleted finding per line with the severity tags
  aligned and evidence on its own indented line. (The earlier raw markdown pipe-table dumped to
  the terminal is gone; the `-d` markdown bundle keeps full markdown.)
- **Terminal-first `saw scan` — "a report is a message, not a file".** `scan` now renders a full
  human report (with full evidence) to `stdout` and **persists nothing by default**; progress goes
  to `stderr`. Output beyond the terminal is delivered through opt-in Strategy "sinks":
  **`--json`** (machine-readable, full evidence, to a pipe), **`--sarif FILE`** (SARIF 2.1.0 for
  GitHub code-scanning upload, evidence redacted), **`--alert`** (open/close a GitHub issue per
  infected repo + post a Slack summary, in-pass, evidence-free), and **`-d/--reports-dir DIR`**
  (opt-in, evidence-redacted `latest.json` + `latest.md`).
- **Release-pipeline hardening:** a **CycloneDX SBOM** of the wheel's resolved dependencies,
  generated in the build job and attached to each GitHub Release; a **`pip-audit` gate** that
  fails the release on a known-vulnerable dependency; and the container scan is now a **Trivy
  gate** (build → scan → push) that blocks a fixable critical/high *before* the image is pushed.
- **Public GitHub Action moved to its own repository, [`Ndevu12/strix`](https://github.com/Ndevu12/strix)**
  ("StayAwakeBot Strix" on the Marketplace): adopt the security sentinel with
  `uses: Ndevu12/strix@v1`. Strix is a thin composite Action that installs the published
  `stayawakebot` scanner from PyPI and runs `saw scan` (gating on its exit code) — the detection
  engine stays in the package, so no scan logic is duplicated. The in-repo `.github/actions/worm-scan`
  composite is kept for this project's own self-gating (`worm-guard.yml`) and from-source pins;
  the superseded root `action.yml` wrapper was removed.
- **Container image on GHCR** (`ghcr.io/ndevu12/stayawakebot`), built and published by the
  release pipeline's `docker` job on each `v*` tag — removes the host Python 3.14 prerequisite.
  Multi-stage, digest-pinned base, non-root, built from the same wheel as PyPI, with SLSA
  provenance + SBOM attestations and a Trivy scan. Adds `Dockerfile` and `.dockerignore`.
- Versioned-release pipeline (`.github/workflows/release.yml`): tag-triggered build →
  self-scan gate → PyPI publish via Trusted Publishing (OIDC, no stored token) with PEP 740
  attestations → GitHub Release. Manual `workflow_dispatch` path publishes to TestPyPI.
- `docs/RELEASING.md` maintainer runbook (one-time PyPI/TestPyPI Trusted-Publisher setup,
  release steps, and the remaining hardening backlog: SBOM, protected-environment reviewers).
- This changelog.

### Changed
- **`saw scan` is read-only — detection only.** Remediation moved out of `scan` into `saw fix`
  (the old `scan --fix`/`--apply`/`--pr` are gone). Scope is **local by default**; `--remote`
  (or naming `--user`/`--org`) scans GitHub instead of local — one scope per run.
- **`saw scan`'s exit code is now the verdict, unconditionally** (`0` clean / `1` infected) — the
  `-f/--fail` (and legacy `--fail-on-findings`) flag is gone; a CI gate just checks the exit code.
  `saw audit` keeps its own `-f/--fail`.
- **Security reports are no longer committed into the repo.** Durable records now live outside the
  repo tree — GitHub code-scanning (SARIF, uploaded not committed), GitHub issues + Slack, and CI
  artifacts.
- **Minimum Python lowered to 3.11** (`requires-python >=3.11`, was `>=3.13`), with a CI test
  matrix across **3.11–3.14** so the supported range is verified on every push. The code never
  needed 3.13, so this fixes the confusing `pip install` failure on 3.11/3.12. The published
  wheel is unchanged (pure-Python — one artifact for every supported version).
- **Health alerting now keeps one self-updating issue per project** instead of opening a new
  `[DOWN]` issue every run. The GitHub issue is the source of truth (found by a stable hidden
  marker, not a history flag), so a lost/rebuilt history can't produce duplicates: while a
  project is down the body is refreshed **silently**, a comment is posted **only on state
  transitions** (first DOWN, then recovery), and the issue is **closed on recovery** (with a
  configurable `consecutive_healthy_before_recovery` debounce). The body now names the **failing
  dimension** (status / latency / keyword / TLS) — previously a keyword/latency/TLS failure showed
  a bare "DOWN" with no reason — and includes a collapsed incident log of recent transitions.
- **Lowered the minimum Python to 3.13** (`requires-python >=3.13`, was `>=3.14`) — the code
  uses no 3.14-only features, so this widens who can `pip install stayawakebot`. Verified by
  running the full test suite on a real Python 3.13 interpreter (96/96 pass).
- **Distribution renamed to `stayawakebot`** on PyPI (`stayawake` is owned by an unrelated
  project). The import package and console scripts are unchanged — only `pip install <name>`
  differs.
- Version is now derived from the git tag via `hatch-vcs` instead of being hand-edited in
  `pyproject.toml`.
- The source distribution (sdist) is now an explicit allowlist (`src/`, README, LICENSE,
  CHANGELOG, pyproject) so it no longer ships `reports/`, `.github/`, or local config.
- `hatch-vcs` now derives the version only from `vX.Y.Z` tags (`git_describe_command` match),
  so the moving Marketplace major tag (`v1`) cannot be mistaken for the package version.

### Removed
- **`saw scan --fix` / `--apply` / `--pr`** (remediation is now `saw fix` / `saw discard`) and
  **`saw scan --local` / `--local-only`** (local is the default; `--remote` is the scope toggle).
- The `saw run`, `saw report`, and standalone `saw alert` verbs. The scan→report→alert pipeline is
  gone: `scan` renders to the terminal and `--alert` pushes the durable record in the same pass.
- The legacy `stayawake-security-{scan,report,alert,remediate,audit}` console scripts. `saw` is now
  the only local security surface; the `stayawake-health-*` scripts are unchanged.

### Fixed
- **Report writing no longer crashes a completed scan when the reports directory is
  unwritable** (read-only filesystem or a bind-mount owned by another user — e.g. the
  documented `docker run -v "$PWD:/repo:ro" …` as the image's non-root user). A scan's
  verdict is its exit code; report persistence is best-effort, so an unwritable directory now
  prints a warning and falls back to a temp dir instead of raising. The container also
  defaults reports to a writable path (`STAYAWAKE_REPORTS_DIR`), and the docs show a
  `--user "$(id -u):$(id -g)"` invocation for writing the report back to the host.

### Security
- **Git-recovery remediation — never corrupts valid code.** An injected code-loader payload is
  recovered from the file's last clean committed version (the real original), or deferred to manual
  review with the exact `git checkout` command — the scanner never surgically edits a source file,
  so a fix can't leave broken code. Only a dense packed payload line carrying a known loader literal
  is auto-dropped; anything that might be legitimate (a real `fromCharCode` line, mixed code) defers.
  Originals are backed up to `.malware-quarantine/`, and a fix PR aborts rather than open over a
  still-infected tree.
- **Remediation TLS + safety hardening.** The GitHub API verifies TLS against a bundled `certifi`
  CA set (fixes `CERTIFICATE_VERIFY_FAILED`); API errors go to `stderr` only (never pollute
  `--json`/reports); and the API is **pre-flighted before any push**, so a broken environment or
  bad token fails fast instead of force-pushing branches to every repo.
- **Evidence redaction in persisted artifacts.** Any report written to disk (`--sarif`, `-d`) now
  stores a fingerprint `{sha256, preview (first 24 chars), len}` instead of the raw payload; full
  evidence appears only on the live terminal (`stdout`/`--json`). In-tree report files were
  redundant, tamperable, and re-distributed live malware payloads — hence terminal-first output and
  no committed security reports.

## [0.1.0] - Unreleased

Initial public release: Health sentinel (uptime monitoring) and Security sentinel
(supply-chain worm detection, remediation, prevention) under one `stayawake` package.

[Unreleased]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ndevu12/stayAwakeBot/releases/tag/v0.1.0
