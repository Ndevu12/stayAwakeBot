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

### Fixed
- **The README's quick-start scan command did not work.** It passed `--local`, a flag removed in
  0.1.6 — local is the default and `--remote` is the scope toggle — so following the README produced
  `unrecognized arguments: --local`. The README now leads with the security sentinel and shows
  commands that run.
- `saw audit`'s scope note no longer refers readers to a document that is not published.

## [0.5.0] - 2026-08-14

### Fixed
- **`saw audit` no longer misses a start-up entry whose interpreter is capitalised, or whose payload is named after one.** An entry running the standard python.org build of Python — whose executable is capitalised — was reported as nothing at all, however suspicious its payload; and a payload file named after an interpreter, such as `node.something.js`, was never read for content. Both are fixed, and a container command written with different capitalisation is again recognised as running elsewhere rather than on this host.
- **`saw audit` no longer stops reading a start-up script partway through, and no longer reports an agent that creates a temporary file as active persistence.** A start-up entry could contain shell that caused the rest of it to go unexamined, so anything after that point was never reported. Separately, an entry that made a temporary file in the ordinary way — the idiom stock system scripts use — could be reported as active host persistence, withholding the rotation all-clear and exiting `3`. Both are fixed, and `saw audit` now also reports payloads run through a shell trap or a process substitution.
- **`saw audit` no longer reports ordinary system agents as host footholds, and no longer misses a multi-line start-up script.** An agent running `tar`, `sort`, `du` or a config-file service with a `-c` option could be reported as active host persistence — withholding the rotation all-clear and exiting `3` — while a start-up entry whose shell script spans several lines was reported nothing at all. Both are fixed, and entries launched through `env`/`sudo` wrappers are now read correctly rather than skipped.
- **`saw audit` now catches a start-up entry that runs a scratch-directory payload with no punctuation in front of it**, such as a systemd `ExecStopPost=/bin/sh -c '/tmp/x &'`. It was reported only when a shell operator preceded the path.
- **`saw audit` no longer reports a start-up entry as an unattributable foothold on ordinary code.**
  A shell-shaped check was being applied to payload text written in other languages, where the same
  punctuation is routine — a JavaScript template literal, a default value, a comment. Signed,
  package-installed software could be reported as active host persistence, which withholds the
  rotation all-clear and exits `3`. Detection of the real shapes is unchanged, including start-up
  entries that run code from a world-writable scratch directory.
- **`saw audit` now says that it does not look for Windows start-up entries.** Persistence
  enumeration covers macOS and Linux user-scope locations only, so on Windows the audit finds no
  start-up entries because it examines none — not because there are none. It previously reported that
  silently, which reads as a clean host. The scope note names the gap on every platform, and on
  Windows the report no longer claims to have read a persistence surface. Presentation only: no new
  finding, and the verdict and exit code are unchanged.

- **An audit check that could not be completed no longer looks like an ordinary review note.**
  When `saw audit` cannot fully read the persistence surface it withholds its all-clear and says so
  — but that "could not establish this" state was rendered identically to a low-priority nudge, so a
  run that deliberately declined to certify could be read at a glance as a clean one. It is now
  visually distinct from both a nudge and an act-now warning. Audit rows also align consistently,
  which they previously did not across the two markers.
- **`saw scan` no longer reports INFECTED on published, benign packages.** A loader fingerprint
  collided with ordinary minified code, so vendoring a large published bundle — or running
  `--deep` on a project that depends on one — could fail your scan with an infected verdict and a
  non-zero exit. If a scan failed on a dependency you had no other reason to doubt, re-run it. The
  detection that catches this worm family is unchanged, and remediation is unaffected: a partially
  cleaned file that still carries loader code is still refused as "fixed".

### Added
- **A new confirmed indicator for the same worm family**, covering a marker the earlier fingerprints
  missed.

## [0.4.1] - 2026-08-11

### Fixed
- **`stayawake-health-check` failed on startup instead of running its checks.** If you run it on a
  schedule, its results were not being recorded — re-check your monitoring coverage. It now runs
  normally.

### Removed
- The `--reports-dir` flag on `stayawake-health-check`. The sentinel has written no report files
  since 0.1.8, so the flag had no effect.

### Changed
- **The availability status issue is now filed only where you configure it.** Set
  `settings.alert_repo: "owner/name"` in the health config; there is no default. With it unset no
  issue is written, while the check still runs, still prints results, and still sets its exit code.
- Documentation reorganised: the public repository carries product documentation. Install, usage,
  configuration, the CLI reference and licensing are unaffected.
- `saw audit` states the boundary of what it examined, so a clean result is not mistaken for a
  whole-host all-clear.
- This changelog now follows the Keep a Changelog standard. Released versions, dates and compare
  links are unchanged.

### Security
- Bumped the pinned self-scan engine used by the CI gate and the release self-scan to current `main`,
  so both validate against the same scanner that ships.

## [0.4.0] - 2026-08-04

### Added
- **`saw audit` reports whether credential rotation is safe**, and exits `3` when it is not, or could
  not be verified. `3` is additive and distinct from infected (`1`) and error (`2`); every existing
  zero/non-zero consumer still fails safe.
- **`saw audit` reports start-up entries it cannot attribute to installed software**, and background
  agents that re-run on a schedule — including ones whose network destination is otherwise ordinary.
  Disabled on ephemeral and CI hosts.
- **`saw scan` detects payloads that delete the user's home directory**, reported distinctly
  according to whether the deletion is recoverable, since that is the first question after a wipe.
  Covers POSIX shells, Windows batch and PowerShell.
- **`saw fix` can recover a file introduced by an evil merge.** The recovered version is never
  applied automatically — it lands as a review-required change the operator must approve.
- `saw scan` clean output notes that a repository scan is not a host all-clear.

### Changed
- Evil-merge findings are graded by the strength of their corroboration; the strongest are now
  reported as confirmed rather than suspicious. The same merges and paths are flagged as before.
- An evil-merge finding now gives history guidance — naming the commit and the files it introduced —
  rather than offering a file edit. `saw fix` never rewrites history.
- Where environment affects how a destructive finding should be read, the finding says so. Severity,
  verdict and exit code never vary with environment.

### Fixed
- `saw fix` no longer reports a repository "already clean" when its only findings were heuristic. It
  lists them and defers to review. Exit code unchanged, and heuristics are still never auto-fixed.

## [0.3.1] - 2026-08-03

### Fixed
- `saw hook` clone and pull warnings state explicitly what to avoid until the code is trusted, and
  show progress so a scan never looks stuck.

## [0.3.0] - 2026-08-03

### Added
- **`saw hook` — scan on clone.** `saw hook install` seeds git's template directory so future clones,
  pulls, branch switches and rebases are scanned before you install dependencies, build, or open the
  repository in an editor. A clone scans the full tree; an update scans only what changed. It is
  read-only and offline, warns rather than modifies, and can never break a git command. It uses the
  packaged signatures and your own allowlist — never one supplied by the repository being scanned.
  `saw hook uninstall` reverses it, `saw hook status` shows state, `SAW_HOOK_DISABLED=1` disables it
  per shell, and `SAW_HOOK_TIMEOUT` (default 60s) bounds it — a scan that times out reports the tree
  unverified, never clean.

## [0.2.0] - 2026-08-03

### Added
- **`saw scan -j/--jobs N` scans concurrently.** A multi-repository sweep scans several repositories
  at once, and a single large repository splits its files across workers. The default is `auto` — a
  small scan stays sequential, a large one uses one worker per core. `-j 1` forces sequential;
  `settings.jobs` sets the default and `settings.parallel_min_files` the floor. Results are
  byte-identical whether run with one worker or many, a failed worker still fails the scan closed,
  and `Ctrl-C` stops in-flight work immediately.
- `saw fix` and `saw guard` accept `-j/--jobs N` for multi-repository sweeps, with the same defaults
  and guarantees. `saw audit` is excluded — it has no multi-repository sweep.

### Changed
- **Scans are substantially faster with identical results** — roughly 1.9× on a 2,000-file tree, and
  it compounds with `-j`. No new flags.
- Scan progress is a live board when running concurrently. Piped, CI and `--no-stream` output is
  unchanged.

## [0.1.19] - 2026-08-02

### Changed
- **GitHub App authentication works on a base install**, with every install method; the optional
  `pyjwt[crypto]` extra is no longer needed and has been removed.
- `saw auth` output is formatted consistently with `saw audit`.

### Fixed
- A GitHub App now works across every account and organisation it is installed on, not only the
  personal account.

## [0.1.18] - 2026-08-02

### Added
- `saw guard setup` installs a complete CI gate: it scans, opens a single rolling fix pull request on
  an infected verdict, and raises a self-closing issue when the pinned scanner drifts.

### Changed
- The App registration flow binds an anti-CSRF nonce.
- Push-failure messages distinguish a bad credential from a missing permission.
- Untrusted paths are sanitised when displayed.

## [0.1.17] - 2026-07-31

### Added
- `saw auth app register` — register and manage a StayAwakeBot GitHub App.
- `saw doctor` reports GitHub App readiness.

### Fixed
- `saw auth` no longer crashes on a default install without the optional App extra.
- A repository-access denial is reported as such, rather than as missing write scopes.

### Security
- The GitHub App private key is no longer written with a window in which it is readable by others.

## [0.1.16] - 2026-07-23

### Changed
- A long result no longer floods the terminal. Lengthy scans show a summary dashboard on screen and
  write the full detail to a report file, whose path is highlighted.

## [0.1.15] - 2026-07-21

### Added
- `saw scan --deep` content-scans installed dependency code. Opt-in, because it adds time on a large
  dependency tree.
- `saw scan` tells you how to fix a flagged dependency, not just that it is flagged.
- `saw audit` detects a cached GitHub credential on Linux and Windows, not only macOS.
- `saw audit` flags two further editor auto-execution surfaces.

### Changed
- `saw audit`'s cached-credential finding explains what it does and does not mean, rather than
  implying the credential should be removed.

### Fixed
- Base64 tokens, key arrays and inlined assets are no longer flagged as packed payloads.
- A non-regular file in a scanned repository can no longer hang a scan.

### Security
- `saw`'s own file write and delete paths are hardened against symlink write-through.

## [0.1.14] - 2026-07-20

### Added
- `saw guard check` verifies a repository's CI gate; `saw guard setup` installs or updates it.
- `saw audit --verify` content-scans a suspicious host artifact.
- `saw scan` flags a repository that ships a write-redirect symlink.

### Changed
- `saw guard check` and `saw guard setup` discover and sweep repositories like `saw scan` and
  `saw fix`.
- `saw audit` right-sizes its incident-response guidance to the evidence, and describes weak
  indicators honestly rather than accusingly.
- `saw audit`'s report is easier to read.

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

[Unreleased]: https://github.com/Ndevu12/stayAwakeBot/compare/v0.5.0...HEAD
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
