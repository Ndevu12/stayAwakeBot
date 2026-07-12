# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Branded first-run welcome for `saw`, plus a `saw intro` tour (#1177).** Bare `saw` now prints a
  designed welcome — the mint "SAW" wordmark, tagline, a *Get started* block, and links — instead of
  the plain argparse dump; `saw intro` (alias `welcome`) gives the fuller tour. In the spirit of a
  supply-chain tool, the welcome flexes the constraint: **zero code runs at install** (pip has no
  post-install hook — the very vector `saw` hunts), so first contact is the first *invocation*, not
  install time. No state files, **no new dependencies** (pure ANSI + `print`). Colour is decided by a
  new single source of truth, `core.terminal.color_level()` (truecolor → 256 → 16 → none), which the
  security report sink now shares too: it honours `NO_COLOR`, `CLICOLOR_FORCE`, `CI`, `TERM=dumb`, and
  a real TTY — so piped / scripted / CI `saw` stays clean plain text, and `saw <cmd> -h` is untouched.
- **Sweeps INSTALLED dependencies' entry files for loader fingerprints — a novel malicious package
  whose payload runs on `require` (#1164).** A malicious npm package can carry no known-bad identity
  and no postinstall, yet still run on import via a loader in its **main/bin entry file**. `node_modules`
  is content-pruned, so that entry is invisible today. The installed-package audit now runs **only the
  confirmed code-loader fingerprints** (reused via `build_content_sig`) on each installed package's
  resolved entry file(s), flagging a match as `installed-entry-loader` (INFECTED). Targeted, not the
  brute-force node_modules scan an earlier value study rejected: **0 FP across 800 real entry files in
  ~0.5s** (vs ~40–60s to scan every file). Entry paths that escape the package dir are dropped (never
  read); bounded to 16 entries per manifest. Python wheels expose no such entry → nothing to sweep.
- **Scans INSTALLED dependencies' npm lifecycle hooks — the postinstall vector the lockfile audit
  can't see (#1164).** A malicious dependency's `postinstall` lives in `node_modules/<dep>/package.json`,
  which is pruned from traversal, so the npm-manifest matcher (which only sees the root manifest) never
  reads it. The installed-package audit now checks each installed package's install-time lifecycle hooks
  and flags a known install-time payload — a `setup_bun` dropper or a `curl|wget → sh/bun/node`
  remote-fetch — as `installed-lifecycle-hook` (INFECTED). It applies **only the confirmed** lifecycle
  patterns (reused from the signature DB, one source), **not** the heuristic exec pattern: measured 0 FP
  across realistic legit postinstalls (`node-gyp`/`husky`/binary-downloaders), whereas the heuristic
  `bun/deno/curl/wget` pattern that's fine on *your* root manifest false-positives across hundreds of
  third-party packages. Python wheels carry no such hooks → nothing to scan there.
- **Detects tampered installed Python packages via `.dist-info/RECORD` sha256 (#1164).** A wheel ships a
  `RECORD` with a per-file sha256 — a per-file integrity manifest npm has no offline equivalent for (its
  lockfile hash is over the published tarball, not the extracted tree). The installed-package audit now
  verifies each installed file against its package's own RECORD: a byte mismatch means the file was
  **modified after install** — a payload injected into a dependency — surfaced as SUSPICIOUS
  (`tampered-installed-package`; a local hotfix can also differ, so it's for review, not auto-INFECTED).
  Only entries carrying a `sha256=` hash are checked, so `.pyc`/`__pycache__`/RECORD-self are skipped →
  **0 false positives on a clean install** (measured: 1,332 files, incl. after import generates `.pyc`).
  Fast and RECORD-guided (not a brute-force hash-everything): ~0.4s for a typical venv, with per-file and
  total hashing bounds as a DoS backstop, and RECORD paths that escape site-packages are ignored.
- **Audits the INSTALLED Python tree, not just the lockfile (#1164).** The installed-package audit now
  has a **Python `site-packages` provider** alongside npm — the 2nd `InstalledTree` implementation, which
  froze that interface (it fit without change). It reads each `<name>-<ver>.dist-info/METADATA` (or
  legacy `.egg-info/PKG-INFO`) in a venv and **identity-on-disk**-checks it against the offline malware
  corpus: a known-malicious PyPI package installed on disk is caught (INFECTED) **even if it's not in
  the lockfile** — the postinstall-drop vector. Names are PEP 503-normalized (shared with the resolver),
  and the `site-packages` walk is bounded and never follows symlinks. **GHOST detection is deliberately
  deferred for Python**: `requirements.txt` lists only *direct* deps, so flagging off-lock transitive
  installs would be all false positives (npm's `package-lock` lists transitive, so its ghost check
  stays); identity-on-disk is the FP-safe, high-value half. Verified: 0 false positives across 29 real
  venv packages against the 6,371-entry PyPI malware corpus. Go/Rust/NuGet stay lockfile-only (global
  cache, no project-local tree). First increment of #1164; a complete-lock ghost reconciliation and a
  `.dist-info/RECORD` sha256 integrity check are the noted follow-ups.
- **Closes the last read-guard blind spots: non-source bodies, disguised binaries, escaping symlinks
  (#1146).** Three residual ways a payload could sit in a spot the scanner skipped, each closed without
  introducing false positives (a value study first dropped the FP-prone parts):
  - **Non-source file bodies** — an oversized (`>2 MB`) or NUL-laden file under a benign extension
    (`.bin`, `.log`, a fake `.png`) used to be skipped wholesale, so a payload there was invisible. The
    **confirmed content-loader tier** now scans a bounded, NUL-stripped head+tail of these files. Only
    that tier runs here — the density/whitespace heuristics stay extension-gated to source, because the
    confirmed regexes are FP-safe on real binary bytes (measured ~0 FP) while the heuristics are not.
  - **Magic-byte masquerade** — the existing "font whose bytes are actually a script" check is extended
    from fonts to images/wasm/pdf (`BINARY_MAGIC`): a file whose extension claims a binary format but
    whose head lacks that format's magic bytes and reads as text/JS is flagged. Real files start with
    their magic, so the check short-circuits (measured 0 FP on 534 real binaries). SVG is excluded (it
    is legitimately text).
  - **Symlink escape** — a **directory** symlink resolving OUTSIDE the repo root is reported (heuristic
    → SUSPICIOUS): `followlinks=False` means its contents are never walked, so it can hide a code subtree
    from the scan. It is never followed (`realpath` only canonicalizes — no traversal, loop-safe), and a
    symlink loop/broken link is now a benign skip instead of a fail-closed "unreadable file". Scope is
    directory symlinks by design — escaping *file* symlinks (a venv's `bin/python`, tool shims) are
    overwhelmingly benign and are a documented residual, not a finding.
  than `max_file_bytes` (2 MB) was read **head + tail only**, so a payload buried in the *middle* (e.g.
  at ~1.5 MB behind benign padding) was invisible to every matcher — a cost-free evasion (empirically:
  a 3 MB bundle with a `fromCharCode(127)` loader fingerprint spliced at offset 1.5 MB scanned
  **clean**). The
  ContentMatcher now streams the **whole body** in overlapping windows via a new
  `Target.read_source_windows`, so no interior region is skipped. Only the **cheap, line-local confirmed
  content-regex tier** goes full-file; the FP-prone whole-file **density heuristic stays head/tail-bounded**
  as before. Memory stays bounded (one ~2 MB window resident regardless of file size — a 500 MB file is
  never read whole) and **total work is bounded** (files above a 64 MB ceiling fall back to head+tail, so
  a hostile target can't weaponize windowing with one enormous file), line numbers stay exact, and it's
  **verdict-identical** on every existing fixture
  (a ≤ 2 MB file yields a single window equal to the old read). Verified FP-safe against 86 real minified
  bundles > 2 MB (0 false matches across their full interior). Closes blind spot #5 of epic #1141.
- **Audits the INSTALLED dependency tree, not just the lockfile (#1144).** The dependency audit sees only
  what a repo *declares*; the worm's real move is a postinstall that drops a package into `node_modules`
  **without editing the lockfile** — invisible to a lockfile-only audit. A new `installed-package-audit`
  matcher reads what's actually on disk and reconciles it: **identity-on-disk** (an installed
  `name@version` is known-malicious → INFECTED, caught even though the lockfile was untouched) and **ghost
  detection** (a package present on disk but absent from the lockfile → SUSPICIOUS — a near-free set-diff).
  This is the deliberately *targeted* alternative to brute-force scanning every file in `node_modules`,
  which a value study measured as 7–10× more I/O for hundreds of false positives and one narrow catch. It
  runs only when a project-local installed tree exists (a remote clone with no install falls back to the
  lockfile audit), is fully offline, and adds **no dependency** — it reuses the existing resolvers, the
  memoized malware corpus, and the confidence-graded verdict. npm today (`node_modules`); the `InstalledTree`
  provider is the Open/Closed seam for Python (`site-packages`) and Composer (`vendor/`) next.
- **Advisory-DB trust hardening + `saw db status`.** The offline advisory cache is now defended as
  the supply-chain surface it is: the manifest carries a SHA-256 per ecosystem file and every scan
  **verifies it before trusting the data** — a corrupted/tampered cache is skipped (falling back to
  the inline seed) with a loud warning, so it can neither inject false malware nor hide real malware.
  The manifest also carries a deterministic **`snapshot`** fingerprint and a `generated_at` timestamp;
  **`saw db status`** reports snapshot / age / counts / integrity and, with `--require-snapshot` /
  `--max-age-days`, lets CI **pin a reproducible DB**. Behaviour is **fail-open by default** (a
  missing/corrupt DB degrades to the inline seed — never blind on the known campaign); **`saw scan
  --require-db`** (or config `require_db: true`) instead fails **closed** (exit 2) for gates that must
  not silently lose coverage. Phase 6 (final) of the dependency-audit epic.
- **`saw scan -x` / `--external` — the one opt-in that leaves the offline sandbox.** Pass it and `saw`
  runs **installed** external auditors (osv-scanner today; the adapter interface makes pip-audit /
  cargo-audit / bundler-audit / govulncheck / npm audit thin additions) and folds their findings into
  the advisory tier, attributed to their tool (`… (via osv-scanner)`) and de-duped against the offline
  corpus. It's **off by default and stays a deliberate, explicit choice** — not for ergonomics but
  because it's the single thing that crosses the offline guarantee: it spawns subprocesses and a tool
  may send your dependency list to its own servers. Absent tools are skipped; output is parsed as
  **data** (never executed); it **never** changes the verdict or exit code. Phase 5 of the
  dependency-audit epic.
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
- **Dependency CVE advisories — part of a plain scan, never gating.** Malicious packages stay in the
  worm verdict (→ INFECTED, unchanged); ordinary vulnerabilities (CVE/GHSA on a declared dependency)
  are surfaced **by default** in their **own report section**, explicitly informational — they
  **never** move the verdict or the exit code (so "INFECTED" still means "carrying the worm", not
  "has any known CVE"). This is free and offline (the corpus is already loaded for malware, and it
  only appears once `saw db update` has populated a cache); `saw scan --no-advisories` (or config
  `dependency_advisories: false`) suppresses the section. Phase 2 of the dynamic dependency-audit epic.
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
- **Centralized all environment-variable access behind one `core.env` helper.** Every env var the
  app reads is now NAMED and READ in a single module (`stayawake/core/env.py`) instead of scattered
  `os.environ.get("…")` magic strings — the alerters, remediator, advisory-cache dir, pager, colour
  and streaming toggles, and token resolution all go through it, and the duplicated
  `owner, name = GITHUB_REPOSITORY.split("/")` parse is now one `env.github_slug()` (which also can't
  crash on a malformed value, unlike the old bare `split("/")`). One consistency change falls out:
  an env var set to **empty/whitespace now reads as unset everywhere** (values are stripped), so a
  stray blank no longer counts as "set." Internal refactor; no CLI/behaviour change beyond that.
- **Relicensed to AGPL-3.0-or-later + a commercial license (dual licensing), from v0.1.9 onward.**
  stayAwakeBot moves off MIT to a **dual-license** model: **AGPL-3.0-or-later** (free, open source —
  attribution required, and network/hosted use of a modified version must release its source under
  the AGPL) **or** a **paid commercial license** for closed-source / proprietary-SaaS use without the
  AGPL's source-disclosure obligations (see [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md)). The full
  AGPL text now ships as [`LICENSE`](LICENSE) — which also **fixes the container image build**, whose
  `Dockerfile` copied a `LICENSE` that had been deleted (so the GHCR publish failed on every release).
  `pyproject.toml` (`license`, `license-files`) and the image's OCI `licenses` label are updated to
  match. **Releases up to and including v0.1.8 were MIT and remain MIT for those versions** — the new
  license governs v0.1.9+. (Not legal advice; the commercial agreement's terms are separate.)
- **A Python venv's `site-packages` is treated as generated context, like `node_modules`.** Third-party
  installed code where a package can legitimately ship a minified `.js`/data blob — the density /
  whitespace / oversized-line heuristics would false-positive there, exactly as in `node_modules`/`dist`.
  This suppresses **only** those FP-prone heuristics; the **confirmed loader-fingerprint tier is ungated
  and still scans** `site-packages`, so a novel or off-manifest malicious file in a venv is still caught
  (with `InstalledPackageAudit`'s corpus-identity + RECORD-tamper on top). It is *not* an exclusion —
  nothing is pruned from traversal, so there is no name-based hiding spot (the epic #1141 rule).
- **~10s faster scans of repos with no dependency files: the OSV corpus loads lazily (#1163).** The
  dependency audit used to build the offline malware/CVE corpus (`db.load_corpus`, ~273k records, ~10s)
  on **every** scan — even for a repo with no lockfile/manifest to audit. The `AdvisoryStore` now defers
  the build to the first package query, so a repo that resolves no dependencies never pays it (a
  no-lockfile dependency-audit dropped from ~10s to ~0.3s). Both dependency matchers benefit with no
  behavior change; `is_empty()` and inline-seed hits also skip the load. A repo **with** dependencies
  still builds the corpus once (memoized) and produces identical verdicts.
- **The scanner no longer skips `reports/` and `sab-patches/` (#1143).** These were excluded as
  "self-output", but a security report/patch stores **redacted** evidence (sha256 + a short preview),
  not the raw IoC, so scanning them doesn't self-trigger (verified: a target repo containing a real
  saw report scans clean) — and the health sentinel now commits no reports at all (#1149). Excluding
  those two common directory names *globally* was just a free hiding spot when scanning someone
  else's repo, so they're dropped from all three parity sites (`base.py`, `config/security.yml`, the
  worm-scan action fallback). `.malware-quarantine` stays excluded (it holds removed payloads
  verbatim). First step of the epic-#1141 "scan everywhere" un-prune.
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
- **The availability sentinel's file-based reporting.** No more committed `reports/` tree (1,048+
  dated `.md` + `status.json`/`history.json`), no `reporter.py`, no `stayawake-health-report` /
  `-alert` scripts, no `commit-reports` action, and the workflow no longer commits (`contents:
  read`). The sentinel is now ONE command — `stayawake-health-check` checks the URLs and refreshes a
  single self-updating **"Availability status"** GitHub issue whose hidden state block is the whole
  store (debounce counters + recent incidents); Slack + the 🔴/🟢 title are the alert. The reusable
  *"issue as a durable, file-less state store"* mechanism lives in **`core/issue_state.py`** (shared,
  not duplicated). (#1149)
- **`saw scan --fix` / `--apply` / `--pr`** (remediation is now `saw fix` / `saw discard`) and
  **`saw scan --local` / `--local-only`** (local is the default; `--remote` is the scope toggle).
- The `saw run`, `saw report`, and standalone `saw alert` verbs. The scan→report→alert pipeline is
  gone: `scan` renders to the terminal and `--alert` pushes the durable record in the same pass.
- The legacy `stayawake-security-{scan,report,alert,remediate,audit}` console scripts. `saw` is now
  the only local security surface; the `stayawake-health-*` scripts are unchanged.

### Fixed
- **`saw fix --pr` / `--remote` now work under GitHub Actions with the default `GITHUB_TOKEN` (#1176).**
  The remediation preflight validated the token by calling `GET /user`, which GitHub's API marks
  `enabledForGitHubApps: false` — so the Actions `GITHUB_TOKEN` (a GitHub App **installation** token)
  got `403 Resource not accessible by integration`, the preflight read that as "token rejected," and
  auto-remediation aborted with *"No repositories to fix"* even though the token could push. This is
  the exact CI environment the feature targets, so `--pr` never worked there without a PAT. The
  preflight now uses a new `github_api.token_is_valid()` that validates **without** requiring
  user-to-server scope: it accepts a PAT via `/user`, and an installation token via
  `GET /repos/{$GITHUB_REPOSITORY}` (`enabledForGitHubApps: true`, needs only `metadata:read`), with
  `GET /rate_limit` as a liveness floor. It stays **fail-closed** — GitHub validates the token before
  resource visibility, so a bogus/expired token 401s on all three (even on a public repo) and an
  unreachable/broken-TLS API yields nothing, both → rejected (still catches the SSL case the preflight
  was built for). The spurious `403` log line on the happy path is gone (the expected `/user` probe is
  now quiet). Ships in `stayawakebot`; the Strix action picks it up once released.
- **A stale-format advisory cache no longer cries "tampered."** After a `saw` upgrade bumps the
  cache schema, the previous cache (an honest DB written by an older `saw`) tripped the byte-level
  integrity gate, printing `advisory-cache integrity check FAILED … corrupted or tampered` for every
  ecosystem — and `saw db status` / `saw scan --require-db` reported the same. That conflated a
  benign version skew with a genuine tamper; in a security tool, crying wolf on an upgrade trains
  users to ignore the *real* alarm. The load and status paths now check the manifest `schema` first:
  an incompatible cache is diagnosed as **"older format — run `saw db update`"** (one calm line;
  still falls back to the always-shipped inline seed and still fails closed for `--require-db`/CI),
  while `integrity check FAILED / tampered` is now reserved strictly for a **schema-matching** cache
  whose contents don't hash-match the manifest. A **corrupt manifest** — valid JSON but not an
  object, a malformed `ecosystems` map, or non-numeric count fields — now degrades to the inline
  seed / fail-closed gate instead of crashing the scan or `saw db status` on an `AttributeError` /
  `TypeError` (#1137).
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
- **Bumped the worm-guard scanner pin to current main (`sentinel-ref` → merge of #1179).** Catches
  the pin up to the two engine PRs that landed with a `pin-bump-deferred` label — the CI
  installation-token remediation preflight fix (#1176/#1178) and the env-access centralization
  (#1179) — so the gate again runs the current reviewed engine. Both were remediation/refactor
  changes (no detection-logic change), which is why deferral was safe; this is the deliberate
  catch-up bump the in-band pin-freshness gate (#1172) exists to force.
- **Bumped the worm-guard gate's pinned scanner to current main (`sentinel-ref` → merge of #1170).**
  The gate pins its detection engine to a reviewed SHA so a later compromise of `main` can't silently
  change what it runs — but a pin that lags runs an out-of-date engine while you believe you're covered.
  The pin had drifted 20 engine files behind (all of the scan-everywhere epic #1141, the ReDoS-class
  elimination #1156/#1158, and the installed-dependency audit #1144/#1164 landed after it), so the gate
  was scanning every PR with a #1138-era engine. It now points at the current reviewed `main` tip.
- **In-band pin-freshness check so the pin can't silently drift again (#1172).** The pin above lagged
  20 files because the only drift signal was `scanner-pin-drift` — a **weekly** job whose alert is a
  **human-closeable issue**, and which is fully **out-of-band from the merges that cause drift**: it
  can't warn until the next Monday, and closing its issue (as happened) silences it without moving the
  pin. A new `Scanner pin freshness` workflow runs **on every PR**: if the diff changes the detection
  engine (`src/stayawake/bots/security/**`) but does **not** bump `sentinel-ref` in `worm-guard.yml`,
  the check **fails at PR time** — on the exact event that breaks the invariant, not up to a week later.
  Deliberate deferral (e.g. one bump at the end of an epic) is allowed via a `pin-bump-deferred` label.
  The decision is a standalone, GitHub-free script (`.github/scripts/check_pin_freshness.sh`) so its
  logic — including that a floating `sentinel-ref: main` reset does **not** count as a bump — is
  unit-tested (`tests/test_pin_tooling.py`), not buried in YAML. The weekly job stays as a backstop
  for drift from direct pushes that bypass PRs. (Verified against real diffs: the engine PRs #1166–#1170
  that slipped the old pin would each have failed this check.)
- **Made the pin-freshness gate *enforced* and *single-sourced* (#1172).** Two gaps in the check above:
  it wasn't actually blocking anything, and it duplicated the engine-subtree + `sentinel-ref` definitions
  that the weekly drift job also hardcodes. Both closed: (1) **`pin-freshness` is now a required status
  check** in the active `common` ruleset — a bad engine PR is blocked from merging at the same tier as a
  force-push (`non_fast_forward`), not merely shown a red X; the `pin-bump-deferred` label is the
  reviewed escape hatch. (2) The engine subtree, the guard file, and the `sentinel-ref: <40-hex>` token
  now live in **one shared source** (`.github/scripts/_pin_lib.sh`); both the in-band freshness check and
  the out-of-band drift detector (whose logic moved out of workflow YAML into
  `.github/scripts/check_pin_drift.sh`) build on it, so the two paths can't disagree on "what is the
  engine" or "what is a valid pin" — the floating-ref rejection is defined once and covered by
  `tests/test_pin_tooling.py`.
- **Fixed a ReDoS: a crafted repo could hang the scanner (#1156).** The remote-fetch-into-interpreter
  signature (`curl|wget → sh/bash/node/…`) used an unbounded `[^|]*`, which scans to end-of-string at
  every `curl`/`wget` when no pipe follows → **O(n²)**. A hostile target with a large no-pipe
  `curl`-spam string — a `package.json` install hook, a `.github/workflows/*.yml` run step, or a
  `.claude/settings.json` hook command (each under the read cap) — could pin a core for **minutes** in
  a single `re.search`: a cost-free denial of service. The gap is now **bounded** (`[^|]{0,2048}`,
  detection-identical — a real `curl URL | sh` is far shorter). The shape was **copied in three places**
  (the npm-lifecycle signature plus the workflow and structural-json matchers, with comments saying it
  must "never drift"); it is now a **single shared, bounded source** (`REMOTE_FETCH_INTO_INTERPRETER`)
  so it can't drift again. Found during the adversarial verification of #1145 (a pre-existing bug,
  unrelated to that change). Real `curl … | sh` payloads still fire (detection-identical).
- **Eliminated ReDoS as a class: five catastrophic-backtracking patterns fixed + one guard that enforces
  it everywhere (#1158).** A hostile repo could hang `saw scan` for minutes-to-hours in a single
  `re.search` via any of five patterns — each a scan-to-end-of-string retried at every anchor when a
  delimiter is absent: the hidden-whitespace-concealment run (a ~40 KB whitespace line → >20 s), the
  untrusted-`${{ }}`-expression check (`${{`-spam → ~12 s), the Maven `pom.xml` `<dependency>` block
  extractor (`<dependency>`-spam → minutes) and its per-tag `<version>…</version>` extractor (a ~2 KB
  whitespace-filled tag → an O(n³) hang), and the JSONC `/* */` comment stripper reached on every
  `package.json` / `settings.json` (`/*`-spam → hours). Each is fixed **structurally, detection-complete,
  and without an attacker-evadable length cap** (the attacker authors these files, so a fixed bound would
  just be padded past): a boundary-anchor + possessive run for the whitespace case; **linear `str.find`
  extraction** of `${{ … }}` blocks / block comments for the workflow and JSONC cases (an injection with
  an arbitrarily long condition or a literal `${{` in its body is still caught); a *tempered* run that
  stays inside one `<dependency>` block, and a non-overlapping `[^<]*` tag body, for Maven. Crucially,
  instead of a per-matcher ReDoS test (which drifts and misses the *next* pattern), there is now **one
  shared guard** — `test_redos_safety.py` walks the **entire** `stayawake.bots.security` package, collects
  **every** compiled regex (matchers, resolvers, signatures, and ones nested in a dict/list — 48 today)
  and asserts each stays bounded on a battery of hostile inputs, cutting off a runaway with a hard timeout.
  A new quadratic pattern anywhere fails that one test — no new test to write.
- **`saw scan` fails CLOSED when a target can't be scanned (was a fail-open).** A per-target scan
  error — an unreadable or malformed config (e.g. an `allowlist` that isn't a list of mappings), a
  read failure (a file present but unreadable — permission error / restrictive ACL), or a failed
  clone — used to be caught into an empty, clean-looking result while the run exited `0`, so a
  broken config or unreadable target could silently pass a CI gate. Now a malformed `allowlist` is
  rejected up front with a clear message; any **errored** target (including an unreadable file)
  makes `saw scan` exit `2` (never `0`); and an **explicitly-requested target that resolves to zero
  repositories** (a stale glob, or a checkout with no `.git`) fails closed rather than reporting a
  green no-op. A clean scan still exits `0`, an infected one `1`; a bare `allowlist:` (null) is
  accepted as "no suppressions". Surfaced (and re-verified) by adversarial review of the `strix`
  self-gate.
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
