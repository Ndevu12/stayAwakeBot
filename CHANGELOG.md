# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Version-range advisory matching — ~12× more malware coverage.** Advisories mostly encode
  *ranges* (`introduced`/`fixed`/`last_affected`), not explicit version lists — and the dominant
  malware shape is "this package is malware at **every** version." `saw db update` now keeps and
  evaluates those ranges via a self-contained **semver comparator** (covering npm, Cargo, Go,
  Composer, NuGet and all `SEMVER`-typed ranges). Effect on npm alone: the malicious set jumps from
  ~18k to **~216k** packages. To keep a fully-populated corpus lean, the cache is streamed as JSON
  Lines and "whole-package" malware is held in a compact index — a complete npm corpus loads in
  ~**160 MB** (down from ~575 MB naïvely), and only when you've opted into `saw db update`.
  Range evaluation covers **all eight ecosystems** via self-contained comparators (no new
  dependency): semver, **PEP 440** (PyPI), **Gem::Version** (RubyGems) and a best-effort **Maven**
  ordering — all validated on live OSV data. A version a comparator can't parse simply doesn't match,
  so an undecidable bound never raises a false INFECTED. Phase 4 of the dependency-audit epic.
- **Dependency auditing across six more ecosystems.** The dynamic dependency audit now resolves and
  matches **Rust** (`Cargo.lock`), **Go** (`go.sum` / `go.mod`), **Ruby** (`Gemfile.lock`), **PHP /
  Composer** (`composer.lock`), **.NET** (`packages.lock.json`) and **Java** (all Gradle lock formats
  — `gradle.lockfile`, `buildscript-gradle.lockfile`, legacy `gradle/dependency-locks/*.lockfile` —
  plus `pom.xml`) — eight ecosystems in all (with npm + PyPI). Each is a small resolver against the frozen
  interface (Open/Closed: no matcher/store change), and `saw db update` now fetches every ecosystem's
  advisories. Validated on live OSV data (a real malicious package per ecosystem → INFECTED, with
  version formats normalized to the OSV form — Go's `v` prefix, Composer's `v` tag, RubyGems platform
  suffixes, `pkg:cargo`↔`crates.io` naming, …). Phase 3b of the dependency-audit epic.
- **PyPI dependency auditing.** The dependency audit now covers Python projects: a `PyPiResolver`
  reads `requirements.txt` (exact `==` pins), `poetry.lock`, `Pipfile.lock` and `uv.lock`, resolves
  each package (PEP 503-normalized names, so `Flask_Foo` matches a `flask-foo` advisory), and matches
  it against the same seed + offline corpus as npm — `saw db update` now fetches PyPI advisories too.
  Verified on live data (a real malicious PyPI pin → INFECTED). This is the second resolver, which
  **freezes the resolver interface** (`resolve(target) → Purl`s) for the coming Go / Rust / Ruby /
  Composer / .NET / Maven fan-out — each is a new resolver, no matcher change. Phase 3a of the epic.
- **`saw scan --advisories` — a separate, opt-in dependency-CVE tier that never gates.** Malicious
  packages stay in the worm verdict (→ INFECTED, unchanged); ordinary vulnerabilities (CVE/GHSA on a
  declared dependency) are now surfaced in their **own report section**, explicitly marked
  informational — they **never** move the verdict or the exit code. Off by default (so "INFECTED"
  keeps meaning "carrying the worm", not "has any known CVE"); enable per scan with `--advisories`
  or config `dependency_advisories: true` (needs `saw db update`). The advisory corpus matches
  explicit affected versions today; range-based advisories (most CVEs) light up when the version-range
  comparators land. Phase 2 of the dynamic dependency-audit epic.
- **`saw db update` — dynamic, offline malicious-dependency detection.** The dependency audit no
  longer relies only on a hand-maintained blocklist: `saw db update` bulk-downloads the OSV
  malicious-package corpus (OpenSSF malicious-packages, the **GitHub Advisory Database** incl. its
  malware advisories, and OSV.dev) into a local cache — **thousands** of known-bad `name@version`
  records instead of a handful — and every scan then matches against it **offline**. The download
  names only the *ecosystem*, never a package, so it can't leak your dependency graph; scans stay
  network-free and deterministic. The inline seed still ships in the wheel, so detection works with
  **zero setup** — the DB is a superset, never a prerequisite (no cache → seed-only, exactly as
  before). Corpus hits cite their advisory id (e.g. `[GHSA-…]` / `[MAL-…]`) in the finding. Phase 1b
  of the dynamic dependency-audit epic; npm today, more ecosystems to follow.
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
- **Large-fleet result presentation.** A big sweep keeps the terminal a bounded, readable
  **dashboard** — the table only — by **moving the per-finding evidence to the written report**
  (the full Markdown + JSON, to your `-d` dir or a temp dir, with its path printed); **clean rows
  collapse to a count** in the table once the fleet is large (the full inventory stays in
  `--json`/`-d`). So a 200-repo result is never lost to terminal scrollback or buried under
  hundreds of evidence lines — **with no pager by default**, so you're never dropped into `less`.
  `--pager` opts into paging through `$PAGER` (built-in default `less -R`: alternate screen,
  Ctrl+C quits the pager).
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
- **Dependency audit refactored onto a PURL spine (internal; no behaviour change).** The
  `dependency-audit` matcher is now a thin coordinator over a new `bots/security/dependencies/`
  package — a normalized **`Purl`** identity, per-ecosystem **resolvers** (`resolve(target)` →
  `Purl`s; npm/yarn/pnpm moved verbatim into `NpmResolver`), and an injectable **`AdvisoryStore`**
  (still backed by the inline `known_bad` seed). This is the groundwork for dynamic, all-ecosystem,
  offline-first dependency auditing; detection results are byte-for-byte identical. (`load_jsonc`
  moved to a neutral `jsonc` module and is re-exported from `matchers.base`.)
- **`saw audit` now streams like `saw scan`.** Each probe (some shell out to launchctl / systemctl /
  the GitHub API) runs under a per-check spinner on stderr, and the hygiene report types out on
  stdout — so the audit *unfolds* instead of pausing then dumping. Streaming auto-disables when the
  output is piped / in CI (the report stays byte-for-byte identical), and `--no-stream` forces
  plain, instant output. The probe set is now defined once in `hygiene.audit_checks()`, shared by
  `hygiene.audit()` and the CLI, so the two can't drift.
- **`saw` CLI guide rewritten for scannability** ([docs/CLI.md](docs/CLI.md)). Leads with a
  cheat-sheet (command table + copy-paste examples); factors the shared **remote targeting**
  ladder and **evidence/redaction** rules into their own sections instead of repeating them under
  each command; documents the built-in **command aliases** (`s`/`sc`, `au`, `se`, `d`/`doc`,
  `comp`); and gives every command a tight purpose + synopsis + options table. No behaviour change.
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
- **`vscode-allow-automatic-tasks` now matches VS Code's real string value.** The signal only
  matched the boolean `true`, but VS Code writes `"task.allowAutomaticTasks": "on"` (the string
  enum, historically `"auto"`) — so on genuine `settings.json` it silently never fired. It now
  fires for boolean `true` **and** any enabling string (anything but `"off"`), aligned with
  `hygiene.check_vscode()`'s `!= "off"` semantics, and does not fire on `"off"`/`false`/absent. (The
  primary `folderOpen`/font autorun signatures already caught the attack, so this restores a
  silently-ineffective corroborator.)
- **Usage docs corrected** ([docs/USAGE.md](docs/USAGE.md)). The App-auth install used a
  non-existent package (`pip install "stayawake[app]"`) — the distribution is `stayawakebot`, so
  the extra is **`stayawakebot[app]`**. And a stale instruction to "drop `--local`" to scan remotes
  referenced a flag that no longer exists — scope is local by default, and **`--remote`** opts into
  GitHub (one scope per run).
- **Report writing no longer crashes a completed scan when the reports directory is
  unwritable** (read-only filesystem or a bind-mount owned by another user — e.g. the
  documented `docker run -v "$PWD:/repo:ro" …` as the image's non-root user). A scan's
  verdict is its exit code; report persistence is best-effort, so an unwritable directory now
  prints a warning and falls back to a temp dir instead of raising. The container also
  defaults reports to a writable path (`STAYAWAKE_REPORTS_DIR`), and the docs show a
  `--user "$(id -u):$(id -g)"` invocation for writing the report back to the host.

### Security
- **Detects malicious upstream dependencies (T1195.001).** A new `dependency-audit` matcher parses
  `package.json` and the npm / yarn / pnpm lockfiles and flags any dependency — direct **or**
  lockfile-transitive — whose exact `name@version` is on a **data-driven known-bad blocklist** (the
  `malicious-dependency` signature's `known_bad` list in `signatures.yml`, refreshable from JFrog /
  GitHub Security Advisories / OSV). An exact match is **confirmed** (INFECTED). This closes the
  campaign's primary spread vector — a poisoned dependency pulled by `npm install` lands in
  `node_modules` (excluded from scanning) and never touches the repo tree, so an org infected purely
  through a dependency would otherwise scan clean. A `package.json` version *range* is ambiguous and
  deliberately deferred to the lockfile's resolved version (no false positive); behaviorally scanning
  `node_modules` content stays off by default (documented residual).
- **`saw audit` detects host filesystem drop-file artifacts.** A new `check_host_artifacts()` probe
  looks for the ingress-tooling / data-staging files this wave leaves on a developer workstation
  (T1105/T1074): `~/.node_modules`, `/tmp/.npm`, `/tmp/get-pip.py`, a `<hostname>$<username>` staged
  exfil archive, the Windows `Python3127` sideloaded-interpreter layout, and a staged `trufflehog`
  secret-scanner **binary** (not a legit user's `~/.cache/trufflehog` cache dir). It is **FP-bounded
  by corroboration** — a lone weak indicator (a stray `~/.node_modules`) is `info`, while a strong,
  specific IoC or a corroborated set is a `warning`. Because a positive means persistence may be
  live, the finding is wired into the incident runbook and its remediation follows the **rotate-LAST**
  order (isolate → neutralize → then rotate), never rotate-first. Distinct from the runner /
  OS-service *persistence* probes; stdlib-only and degrades to a no-op when paths are absent.
- **Detects whitespace / invisible-character concealment.** A new `whitespace-concealment`
  heuristic flags the *technique*, not just the payload: content pushed off-screen behind a long
  run of horizontal whitespace (the fake-font / `postcss.config` sample buried its payload behind
  ~752 spaces so the line looks empty), or hidden with zero-width / bidi-control characters (the
  "Trojan Source" attack, CVE-2021-42574). It fires even when the concealed payload matches no
  fingerprint and the line is **under** the 2000-char long-line threshold — the previously-confirmed
  blind spot — across `*.js`/`*.mjs`/`*.ts`/`*.json` (incl. a space-padded `.vscode/tasks.json`
  command) and font-as-text files. It is **heuristic → SUSPICIOUS** (wide alignment can rarely
  produce a long run), context-scoped so minified/generated bundles are suppressed, and bounded so
  short alignment, lone aligned characters, and legit emoji zero-width joiners stay clean.
- **Opt-in build-output scanning (`scan_build_outputs`).** Set `scan_build_outputs: true` in
  `config/security.yml` to also inspect build outputs: the project build-output dirs
  (`dist`/`build`/`out`/`.next`) are un-pruned and the obfuscation matcher runs only its
  **self-evident construct checks** (charcode array, exec sink, base64/escape blob) on
  generated/minified paths — the **whole-file density heuristic stays suppressed** (density is
  expected in bundles) —
  emitting an `obfuscated-build-artifact` finding at **`heuristic`** confidence (SUSPICIOUS, never
  INFECTED). A legit dense bundle with no such construct stays clean. Off by default, so the
  FP-safe defaults for ordinary scans are unchanged; this is an inspection aid and does not close
  the documented build-artifact residual.
- **Documented that provenance is not trust, and named the build-artifact residual.** A new
  "Provenance is not trust" section in `docs/SECURITY_ARCHITECTURE.md` (plus a README note) makes
  explicit that `saw` is purely behavioral — it never treats a scanned target's SLSA / PEP-740 /
  sigstore attestation as a trust signal (Shai-Hulud 2.0 shipped valid SLSA Build L3 provenance with
  no CVE). The two intentional build-output suppressions (traversal-pruned `dist`/`build`, and the
  `is_generated_context` obfuscation-heuristic suppression on minified/bundled paths) now carry
  inline rationale, and the residual — a payload minified into a legitimate-looking bundle can evade
  content detection, so the durable guarantee is on hand-authored source + git-history corroboration
  — is recorded in the `obfuscation.py` docstring. A test locks the current default suppression on
  `dist`/`build`/`*.min.js`. No behavior change (opt-in build scanning deferred).
- **Detects planted OS-service persistence — the credential-rotation wiper.** `saw audit` gains a
  `check_persistence()` machine probe that finds the reported `gh-token-monitor` service (and
  lookalikes) by name across the standard systemd unit directories (user + system) and macOS
  `LaunchAgents`/`LaunchDaemons` — a read-only directory listing, so it needs no `systemctl`/
  `launchctl` and degrades to a no-op when those directories are absent, including
  installed-but-not-started units. Because the service is a wiper tripwire (it destroys `$HOME`
  when it detects a credential rotation), the finding leads the incident runbook: **isolate →
  neutralize the service → then rotate credentials LAST**, never immediate rotation. This
  consolidates all wiper/OS-service detection in one probe — the self-hosted-runner check
  (added previously) is now solely about the runner and no longer double-reports the wiper.
- **Extends auto-run detection to AI/agent config — Claude Code hooks (`.claude/settings.json`).**
  The structural matcher previously only understood `.vscode/`; it now also inspects
  `.claude/settings.json` (and `settings.local.json`) and parses the Claude Code `hooks` schema —
  the same auto-execute threat class one config layer over (T1546). A command hook on a
  lifecycle/open event (`SessionStart` etc. — the `runOn: folderOpen` analogue) is **heuristic**
  (SUSPICIOUS — legit projects ship benign hooks); a hook whose command runs a disguised payload
  (remote-fetch → interpreter, a font/binary, or a known loader fingerprint) is **confirmed**
  (INFECTED) on any event. Active-tool-use hooks (`PostToolUse` formatters/linters) and
  permissions-only configs stay clean, and only `.claude/` files are inspected. The existing VS
  Code detection is unchanged.
- **Detects self-hosted GitHub Actions runner persistence — the worm's most durable foothold.**
  Two complementary additions. (1) The repo scanner detects committed runner-registration artifacts,
  two-tier to keep the verdict honest: a file merely *named* `.runner`/`.credentials` is a
  **heuristic** review signal (SUSPICIOUS — it could be empty or unrelated), while a `.runner` whose
  *content* is a real registration (a live `serverUrl`/`gitHubUrl` endpoint) is **confirmed**
  (INFECTED). Basenames match at any depth without firing on near-miss names like `aws.credentials`.
  (2) `saw audit` gains `check_runner_persistence()`, which finds an installed `actions-runner`
  (`.runner` config) and a registered runner / `gh-token-monitor.service` wiper across launchd
  (macOS) and systemd (Linux) — system *and* user scope, including installed-but-not-started units —
  degrading to a no-op when those tools are absent. Because a rogue runner tempts an immediate
  credential rotation — which is exactly the reported wiper tripwire — the finding is wired into the
  incident runbook so the output leads with **isolate → runner offline + registration removed →
  rebuild → then rotate LAST**, never immediate rotation. `saw audit` now composes its checks through
  a single site so the probe can't be silently dropped, and the `SHA1HULUD` runner name in a
  committed install is still covered by the existing exfil content signature (not duplicated).
- **Scans `.github/workflows/*.yml` for planted / impersonated Actions workflows.** A new
  YAML-aware `workflow-yaml` matcher closes the Shai-Hulud 2.0 / Mini CI-persistence blind spot —
  workflow files were walked but never inspected. It flags two **heuristic** (SUSPICIOUS, not
  INFECTED) shapes: an injection-prone trigger (`pull_request_target` / `issue_comment` / `issues` /
  `discussion` / `discussion_comment` / `workflow_run`) that reaches a `run:` step interpolating an
  untrusted `${{ github.event.* }}` field — the "open a Discussion → payload fires" weakness — and a
  workflow masquerading as Dependabot that also uses a self-hosted runner, a remote-fetch-into-
  interpreter `run:`, or an injection expression. A normal `push`/`pull_request` CI workflow that
  only reads vetted inputs stays clean, and the notorious PyYAML `on:` → boolean-`True` key is
  handled so detection isn't silently bypassed. Malformed workflow YAML is skipped, never crashes a
  scan.
- **Detects malicious npm lifecycle hooks in `package.json`.** A new `npm-manifest` matcher reads
  the keys npm auto-runs on `npm install` — `preinstall`/`install`/`postinstall`/`prepare` — and
  flags the Shai-Hulud install-time execution vector: `node setup_bun.js` (dropper) and a remote
  fetch piped into an interpreter (`curl … | bun`) are **confirmed** (INFECTED); Bun/Deno smuggling
  or a bare fetch in an install hook is **heuristic** (SUSPICIOUS). User scripts like `test`/`build`
  and a plain `node` build step are deliberately not flagged, so normal manifests stay clean. Closes
  a gap where an install-time dropper passed a scan cleanly.
- **Detects the Shai-Hulud exfiltration / persistence stage.** New content signatures flag the
  worm's own vanity labels: the attacker-repo/commit branding `Sha1-Hulud: The Second Coming` and
  `A Mini Shai-Hulud has Appeared` (confirmed → INFECTED), and the self-hosted runner name
  `SHA1HULUD` in runner/workflow/service config (confirmed, path-scoped so a prose mention isn't
  flagged). A bare `Shai-Hulud` mention is a separate **heuristic** signal (SUSPICIOUS, not
  INFECTED — benign in write-ups). Closes a gap where a repo already carrying the worm's exfil
  branding or runner registration produced zero signal.
- **Incident-response guidance rotates credentials LAST (wiper-safe).** `saw audit`'s hygiene
  output no longer tells you to rotate an exposed token outright. The Mini Shai-Hulud variant is
  reported to install a host service (`gh-token-monitor.service`) that **wipes the home directory
  when it detects credential rotation**, so rotating while persistence is still live turns
  containment into data loss. When credential exposure is found, the audit now leads with an ordered
  runbook — **isolate → rebuild from clean images → neutralize per-host persistence → then rotate** —
  and the rotation remediation is phrased as the last step with the wiper warning. Documented in
  `docs/SECURITY_ARCHITECTURE.md`.
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
