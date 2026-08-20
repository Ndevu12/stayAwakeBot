# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**What belongs in an entry.** An entry describes what someone *using* a release observes: new or
changed behaviour, flags, compatibility, and fixes they would notice. It does not describe internal
implementation — module layout, refactors, detector or rule internals, thresholds, the inputs an
analysis keys on, coverage gaps, or release-pipeline mechanics. A change with no user-visible effect
does not get an entry. For a security fix, state that the fix shipped and what it means for the
reader, not the mechanism or the weakness it closed.

## [Unreleased]

### Changed
- **The documentation site has moved to <https://saw-docs.ndevuspace.com>.** The previous address
  redirects; update a bookmark if you kept one.

### Fixed
- **A shared link to the documentation shows its preview image again.** The card was addressed with
  a missing separator, so every link preview requested a page that did not exist.

### Fixed
- **`saw audit --verify` no longer treats a clean content scan as reassurance.** Finding nothing
  inside an unusual folder does not make it safe — a staging tree holds ordinary packages, and the
  code that used them can be gone from disk — so the folder keeps the same "verify this is yours"
  standing it had before the scan, and the report says how many files it could not read (archives
  and binaries are not opened). A scan that finds worm markers still escalates as before.

### Fixed
- `saw guard --remote` no longer blames your token when a repository simply has no CI.
- `saw guard setup --pr` opens pull requests instead of silently doing nothing.
- `saw guard` recognises a gate installed by any mechanism, and no longer overwrites an existing one.
- `saw audit --repo` no longer reports a protected repository as unguarded.
- `saw guard` is documented alongside the other commands.

## [0.1.13] - 2026-07-15

### Added
- The scanner recognises further dynamic code-execution forms, reported as heuristic signals so they
  inform without failing CI or triggering remediation.

### Fixed
- `saw fix` no longer reports a fix it did not make when commit signing fails.

## [0.1.12] - 2026-07-15

### Added
- `saw fix` shows per-finding manual-review guidance rather than only a count.

### Security
- Updated the container base image for a fixable CVE, so the published image builds again.
- `saw fix` recovery no longer drops legitimate code that shared a line with a payload.
- Hardened what `saw fix` recovers from, and the check that the result is payload-free.

## [0.1.11] - 2026-07-12

### Added
- A first-run welcome, plus a `saw intro` tour.

## [0.1.10] - 2026-07-11

### Fixed
- `saw fix --pr` and `--remote` work under GitHub Actions with the default `GITHUB_TOKEN`.

## [0.1.9] - 2026-07-10

### Changed
- Relicensed to AGPL-3.0-or-later with a commercial option, from v0.1.9 onward. Releases up to and
  including v0.1.8 remain MIT.

## [0.1.8] - 2026-07-10

### Added
- Dependency CVE advisories as part of a plain scan, never gating.
- `saw db update` and `saw db status` — an offline advisory corpus with integrity checking.
- Dependency auditing across several more ecosystems, including PyPI, with version-range matching for
  substantially wider coverage.
- Audits the installed dependency tree, not only the lockfile, and detects tampered installed Python
  packages.
- `saw scan -x`/`--external` — the one opt-in that leaves the offline sandbox.

### Changed
- Python virtual environment directories are treated as generated context, like `node_modules`.
- Repositories with no dependency files scan about 10s faster.
- `saw audit` streams progress like `saw scan`.
- The CLI guide was rewritten for scannability.

### Removed
- The availability sentinel's file-based reporting.

### Fixed
- A stale advisory cache no longer reports as tampered.
- An editor auto-run setting is matched against its real value.

### Security
- `saw scan` fails closed when a target cannot be scanned; it previously failed open.
- Fixed a pathological regular-expression case in which a crafted repository could hang the scanner.
- Added detection for malicious upstream dependencies, planted OS-service persistence, self-hosted
  runner persistence, planted or impersonated CI workflows, malicious npm lifecycle hooks, AI agent
  auto-run configuration, host drop-file artifacts, invisible-character concealment, and the known
  worm's exfiltration and persistence stage.
- Opt-in build-output scanning.
- Incident-response guidance rotates credentials last.

## [0.1.7] - 2026-06-30

_No user-facing changes were recorded for this release._

## [0.1.6] - 2026-06-30

### Added
- `saw fix` — remediate on a branch, with `--pr` to publish; `saw discard` — undo a fix.
- Discoverable remote targeting, and result presentation for large fleets.

### Changed
- `saw scan` is read-only: detection only.

### Removed
- `saw scan --fix`, `--apply` and `--pr` — remediation is now `saw fix` and `saw discard`.
- `saw scan --local` and `--local-only` — local is the default, and `--remote` is the scope toggle.

### Security
- Remediation recovers a payload-carrying file from its last clean committed version, or defers to
  manual review with the exact command to run. It never edits a source file surgically, so a fix
  cannot leave broken code. Originals are backed up, and a fix pull request aborts rather than open
  over a still-infected tree.
- The GitHub API verifies TLS against a bundled CA set, API errors go to stderr only so they never
  pollute a report, and the API is pre-flighted before any push.

## [0.1.5] - 2026-06-29

### Added
- A readable terminal report; `saw scan` is terminal-first.

### Changed
- `saw scan`'s exit code is the verdict, unconditionally.
- Security reports are no longer committed into the repository.

### Removed
- The `saw run`, `saw report` and standalone `saw alert` verbs. `scan` renders to the terminal and
  `--alert` pushes the durable record in the same pass.
- The legacy `stayawake-security-*` console scripts. `saw` is the only local security surface; the
  `stayawake-health-*` scripts are unchanged.

### Security
- A report written to disk stores a fingerprint rather than the raw payload; full evidence appears
  only on the live terminal.

## [0.1.4] - 2026-06-25

_No user-facing changes were recorded for this release. The unified `saw` CLI first shipped here and
is described under 0.1.5._

## [0.1.3] - 2026-06-25

### Changed
- Minimum Python lowered to 3.11.
- Health alerting keeps one self-updating issue per project: it names the failing dimension (status,
  latency, keyword or TLS), comments only on state transitions, and closes the issue on recovery
  after a configurable debounce.

### Fixed
- A completed scan no longer crashes when the reports directory is unwritable — for example a
  read-only or another user's bind-mount. The verdict is the exit code and report persistence is
  best-effort, so it warns and falls back to a temporary directory.

## [0.1.2] - 2026-06-25

_No user-facing changes were recorded for this release._

## [0.1.1] - 2026-06-25

### Added
- A container image on GHCR.
- The public GitHub Action moved to its own repository,
  [`Ndevu12/strix`](https://github.com/Ndevu12/strix).

### Changed
- Distribution renamed to `stayawakebot` on PyPI. The import package and console scripts are
  unchanged — only `pip install <name>` differs.
- Minimum Python lowered to 3.13.

## [0.1.0] - 2026-06-19

Initial public release: Health sentinel (uptime monitoring) and Security sentinel (supply-chain worm
detection, remediation, prevention) under one `stayawake` package.

[Unreleased]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.6.2...HEAD
[0.6.2]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.19...v0.2.0
[0.1.19]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.18...v0.1.19
[0.1.18]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.17...v0.1.18
[0.1.17]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.16...v0.1.17
[0.1.16]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.15...v0.1.16
[0.1.15]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.14...v0.1.15
[0.1.14]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.12...v0.1.13
[0.1.12]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Ndevu12/stayAwakeBot/releases/tag/v0.1.0
