# StayAwakeBot — Security Sentinel Architecture

A worm-hunting / auto-fixing / preventing bot that reuses the toolkit's proven
`gather → report → alert → commit` pipeline. Built data-driven and layered so new
threats are added as configuration, not code.

## Pillars
- **Detect** — scan local & remote repos for known indicators (IoCs) and evil merges.
- **Report/Alert** — terminal-first: full human report on `stdout` (full evidence); durable
  records via opt-in sinks — `--json`, redacted `--sarif`/`-d`, and `--alert` (GitHub issue + Slack).
- **Auto-fix** — quarantine/strip via PRs, never force-push (dry-run by default).
- **Prevent** — reusable CI gate + pre-commit + CI-token hardening.

## Layers (SRP)
```
signatures (data) ─► signature engine ─► matchers ─► findings ─► scanner ─► sinks (terminal · json · sarif · alert) ─► remediator(PR)
```
- **Signatures** (`src/stayawake/bots/security/data/signatures.yml`, packaged): IoCs as data. New threat = new entry.
- **Matchers** (`security/matchers/`, Strategy): one technique each, selected by a
  signature's `matcher` field — `content`, `filename`, `structural-json`, `heuristic`, `git-history`.
- **Targets** (`security/targets/`, DIP): `LocalRepoTarget` and `RemoteRepoTarget`
  (sandboxed shallow clone, read-only) share one interface.
- **Scanner** (`security/scanner.py`): runs matchers over a target → `ScanResult`; applies allowlist.
- **Findings** (`security/models.py`): typed `Severity`/`Finding`/`ScanResult`.
- **Shared** (`core` + `core/adapters`): reused by both bots (DRY).

## Safety / threat model
- **Never executes scanned code** — static analysis + git plumbing only.
- Remote targets cloned into ephemeral sandboxes (`core.hooksPath=/dev/null`, no prompts), removed after.
- Remediation defaults to **report-only**; fixes go through **PRs**, never force-push to main.
- **No false "fixed"**: after applying, the remediator re-scans and quarantines any residual
  finding, **aborting the commit/PR if the tree is not clean** — it never ships a still-infected
  file under a remediation label.
- **Evasion-resistant reads**: source files are scanned even when they carry NUL bytes (one NUL
  must not mark a payload "binary") or exceed the size cap (head+tail is scanned). Content
  matching is case-insensitive.
- **No self-leak**: quarantine backups (which hold live payloads) are kept out of commits —
  `.gitignore` is enforced *and* any pre-existing tracked quarantine dir is untracked before
  staging; the scanner excludes its own `reports/` output so it never re-flags its evidence.
- The bot's `contents: write` token is high-value — the prevention layer scopes it and hardens the
  auto-commit step (this is the exact surface the worm used to inject its payload via an evil merge).

## Provenance is not trust (and the build-artifact blind spot)
`saw` is a **behavioral** scanner: it judges *content*, never *pedigree*. A valid SLSA / PEP-740 /
sigstore attestation proves a build pipeline ran over some input — it says **nothing** about whether
that input source was clean. The Shai-Hulud 2.0 wave made this concrete: compromised packages were
republished carrying **valid SLSA Build L3 provenance** and **no CVE was issued**, so both
provenance-trusting and CVE-anchored tooling produced zero signal.

- **`saw` never treats a scanned target's attestation as a reason to skip or trust it.** There is no
  "has provenance → skip scanning" path anywhere in the scanner, and none should be added. Provenance
  is provenance-of-build, not trust-of-content.
- **Build outputs are deliberately out of scope for the obfuscation heuristic** — via two independent
  layers: (1) `dist/`/`build/` (and peers) are pruned from traversal in `ScanOptions.exclude_dirs`
  before any matcher runs, and (2) `is_generated_context()` (the `_GENERATED_PATH` predicate in
  `obfuscation.py`) suppresses the density/entropy obfuscation heuristic on minified/bundled/generated
  paths (`*.min.js`, `*.bundle.js`, source maps, lockfiles, …). Minification *is* obfuscation in those
  places, so flagging it would be all false positives. (Known **loader fingerprints** — the content
  signatures — still match anywhere they are actually traversed; only the shape-based heuristic is
  suppressed.) Both `exclude_dirs` are settings-overridable in `config/security.yml`.
- **Residual (named, not a bug):** a payload minified into a legitimate-looking bundle can be
  statistically indistinguishable from a normal bundle, so it can evade content detection. `saw`'s
  durable guarantee is on **hand-authored source** plus **git-history / evil-merge corroboration** —
  the point *before* the worm's payload is baked into a post-build artifact — not on compiled outputs.
  Scanning the source a build is produced from is strictly stronger than trusting the artifact's
  attestation.
- **Opt-in build scanning (`scan_build_outputs: true` in `config/security.yml`).** For deliberate
  inspection you can un-suppress build outputs: the build-output dirs are un-pruned and the
  obfuscation matcher runs only its **self-evident construct checks** (charcode array, exec sink,
  base64/escape blob) on generated/minified paths — the **whole-file density heuristic stays
  suppressed** (density is *expected* in bundles). Findings are `obfuscated-build-artifact` at **`heuristic`**
  confidence (SUSPICIOUS, never INFECTED); a legit dense bundle with no such construct stays clean.
  This is noisier by design (an `atob`/`fromCharCode` in a bundle will flag) and does **not** close
  the residual above — it is an inspection aid, not the durable guarantee.

## Malicious upstream dependencies (T1195.001)
The campaign's *primary* spread is republishing backdoored package versions, so the next
`npm install` is the next victim — the payload lands in `node_modules` (which `saw` excludes) and
never touches the repo tree. `saw` audits what a repo **declares and locks**: the `dependency-audit`
matcher runs per-ecosystem **resolvers** that turn manifests/lockfiles into normalized package
identities (PURLs) and flags any dependency — direct **or** lockfile-transitive — whose
`name@version` is on a **data-driven known-bad blocklist**. An exact match is decisive → **confirmed**
(INFECTED). Ecosystems today (eight): **npm** (`package.json` + npm/yarn/pnpm locks), **PyPI**
(`requirements.txt` + poetry/Pipfile/uv locks), **Rust** (`Cargo.lock`), **Go** (`go.sum`/`go.mod`),
**Ruby** (`Gemfile.lock`), **PHP/Composer** (`composer.lock`), **.NET** (`packages.lock.json`) and
**Java** (all Gradle lock formats + `pom.xml` literal versions). Each ecosystem's version format is normalized to the OSV
form (e.g. Go's/Composer's leading `v`, RubyGems platform suffixes) and a canonical PURL-type ↔
OSV-name table (`ecosystems.py`) bridges e.g. `pkg:cargo` ↔ `crates.io`. The resolver interface is
frozen (Open/Closed), so a new ecosystem is just another resolver. The blocklist is the
`malicious-dependency` seed plus the offline corpus below.

- **Two layers of known-bad data (both offline at scan time):**
  - **Inline seed** — the `malicious-dependency` signature's `known_bad` list in `signatures.yml`,
    which always ships in the wheel. Append `name@version` entries from public advisories (**JFrog**,
    **GitHub Advisories**, **OSV**) for the Shai-Hulud / Miasma campaign. Zero-setup, zero-network.
  - **Dynamic corpus** — `saw db update` bulk-downloads the OSV malicious-package corpus (**OpenSSF
    malicious-packages**, the **GitHub Advisory Database** incl. its malware advisories, and
    **OSV.dev**) into a local cache; scans then match resolved dependencies against it too. The
    corpus is a *superset* of the seed, never a prerequisite (no cache → seed-only). **Trust model:**
    the DATA is dynamic but the SCAN stays offline — `saw db update` is the only network egress, and
    it names only the *ecosystem* (`…/npm/all.zip`), never a package, so it can't leak your
    dependency graph; we never query per-package online. Records are normalized OSV JSON de-duped on
    `id`+`aliases` (OSV.dev already re-exports GHSA). It complements (not replaces) the behavioral
    engine, which stays the backbone.
- **Two tiers, one verdict (mission honesty):** a **malicious** package (OpenSSF / a GHSA *malware*
  advisory) is the worm → it drives the verdict (`confirmed` → INFECTED). A merely **vulnerable**
  package (an ordinary CVE on a legit library) is *not* the worm; surfacing it as INFECTED would
  degrade the verdict to "has any known CVE" and bury real worm signal. So CVEs are a separate
  **advisory tier**, reported in their own section and routed out of the verdict
  (`ScanResult.advisories`, `advisory_only` findings) — they never change the exit code. This tier is
  **on by default** (it's offline and free — the corpus is already loaded for malware); it only
  appears once `saw db update` has populated a cache, and `--no-advisories` / config
  `dependency_advisories: false` suppresses it. Malware is classified by structured signals only
  (`MAL-` id/alias, `database_specific.type == malware`, CWE-506) — never free text.
- **External auditors — the ONE opt-in that leaves the offline sandbox (`saw scan --external`):**
  `saw` can additionally run *installed* vulnerability tools (osv-scanner today; the
  `dependencies/external/` adapter interface makes pip-audit / cargo-audit / … thin additions) and
  fold their results into the same advisory tier, de-duped against the offline corpus and attributed
  to their tool. It stays **off by default and explicit** — not for ergonomics but because it is the
  single thing that breaks the offline guarantee: it spawns subprocesses, and a tool may send the
  dependency graph to its own servers. Everything else in a scan is offline. When invoked: absent
  tools skipped silently; tool output parsed as **data**, never executed; subprocess is an argv list
  (no shell) + timeout, in the target's dir (a remote target's clone sandbox). Still never moves the
  verdict.
- **Decisions / residuals (deliberate):**
  - A `package.json` **version range** (`^4.2.11`) is ambiguous — it may or may not resolve to the
    bad version — so ranges are **not** matched; the lockfile's resolved version is the source of
    truth. A range-only project with no lockfile is a documented residual.
  - **Behaviorally scanning `node_modules` content stays off by DEFAULT** — it is expensive
    (~10–60s on a big tree) and the density heuristic false-positives on minified code, so a normal
    scan checks only each installed package's **entry points** (`main`/`bin`) plus its identity /
    ghost / lifecycle-hook signals. A loader payload in a **non-entry** file of an on-lockfile package
    is therefore out of a normal scan's scope — and, so a `clean` verdict is not silently hollow, a
    scan of a repo with `node_modules` prints an honest **coverage note** saying exactly that (#1222).
    Two **opt-ins** look deeper, both **CONFIRMED-only** (never the FP-prone density heuristic):
    - **`saw scan --deep`** (#1222) content-scans *every* source file of a repo's installed npm
      packages with the confirmed loader fingerprints (0 false positives measured over 531 MB of real
      vendored code) — catching that non-entry payload. Bounded (per-package file cap + a shared byte
      budget whose exhaustion is reported as a partial-coverage note); npm-only.
    - **`saw audit --verify`** content-scans a *single suspect directory* a host-artifact probe flagged
      (e.g. a `~/.node_modules` in `$HOME`), excludes off, to corroborate that lone weak indicator —
      without changing how `saw scan` discovers or scans repositories.
  - Lockfiles are read **whole** (up to 32 MB, bypassing the scan's head/tail truncation so a large
    `package-lock.json` still parses); a pathological lockfile beyond that cap, and an aliased
    dependency in a *yarn/pnpm* lockfile (npm aliases are resolved via the lockfile's `name` field),
    are residuals.
  - The dynamic corpus matches an advisory by its **explicit versions** *or* its **ranges**. Ranges
    are evaluated per-ecosystem by self-contained comparators (`comparators.py`, no third-party dep):
    **semver** (`SEMVER`-typed + npm/Cargo/Go/Composer/NuGet), **PEP 440** (PyPI), **Gem::Version**
    (RubyGems) and a best-effort **Maven** ordering. A range whose type has no comparator (`GIT`) or
    whose bound a comparator can't parse conservatively does **not** match, so an undecidable range
    never raises a false INFECTED. Because most
    malware says "malware at *every* version" (a lone `introduced: "0"` range), those are held in a
    compact **whole-package** index and the cache streams as **JSON Lines**, so a fully-populated
    corpus (npm alone ≈ 216k malicious packages) loads in ~160 MB rather than ~575 MB.
  - **Cache trust (the DB is itself a supply-chain surface).** Because `saw db update` pulls a
    third-party feed to decide what's malicious, the cache is defended:
    - **Content-hash integrity.** The manifest stores a SHA-256 per ecosystem records file; every
      load re-hashes the file and trusts it ONLY on a match. A corrupted/tampered file is skipped
      (falling back to the always-shipped inline seed) with a loud stderr warning — a tampered cache
      can neither inject false malware nor hide real malware; it is rejected wholesale.
    - **Snapshot pinning.** The manifest carries a deterministic `snapshot` fingerprint (from the
      per-ecosystem content hashes). `saw db status --require-snapshot <digest>` (and `--max-age-days`)
      lets CI pin a reproducible DB; `generated_at` is informational and deliberately outside the
      snapshot so it never perturbs the fingerprint.
    - **Fail-open by default, fail-closed on request.** A missing/corrupt DB degrades to the inline
      seed (never blind on the known campaign) — the safe default. `saw scan --require-db` (or config
      `require_db: true`) instead fails **closed** (exit 2) for CI gates that must not silently lose
      coverage. `saw db status` reports presence, snapshot, age, counts and integrity.
    - **Cache location.** Global by default (`$SAW_ADVISORY_CACHE_DIR` → `$XDG_CACHE_HOME/saw` →
      `~/.cache/saw`); point the env (or `db update --cache-dir`) at a repo-committed dir to pin a
      snapshot for CI.
    - **Residual (honest):** the content hash catches corruption and naive tampering, not a
      sophisticated local attacker who rewrites BOTH a records file and its manifest hash — but that
      requires write access to the cache, i.e. the host is already compromised. Upstream
      *cryptographic* signing is not verified: the OSV exports expose no signature we hold a trust
      anchor for; the download itself is TLS-verified (certifi) from trusted infrastructure.

## Detected vectors (from the live incident)
1. Obfuscated loader in `postcss.config.*` (content + oversized-line heuristic)
2. Fake font payload `public/fonts/fa-solid-400.woff2` (filename + text-in-fontfile heuristic)
3. Camouflage `public/fonts/` dir with "Blockchain Explorer" README (content/heuristic)
4. VS Code `folderOpen` auto-run task running a font via node (structural-json)
5. `.gitignore` worm markers (content)
6. **Evil merges** — content a merge introduces beyond a clean 3-way merge of its parents (git-history)

## Incident response — rotate credentials LAST
**Do not rotate credentials first.** The Mini Shai-Hulud variant is reported to install a host
service (`gh-token-monitor.service` on Linux) that watches for credential rotation and, if a token
is rotated while the persistence is still live, **wipes the home directory** (MITRE T1485). The
reflexive "rotate everything now" reaction is exactly what arms that tripwire — turning containment
into data loss. Respond in this order:

1. **Isolate** the host from the network before anything else.
2. **Rebuild from clean images** — take self-hosted CI runners offline and rebuild affected hosts
   from known-good images (watch for a runner named `SHA1HULUD`).
3. **Neutralize per-host persistence** — rogue OS services (e.g. `gh-token-monitor.service`),
   planted CI workflows, and editor/AI-agent auto-run hooks (`.vscode/`, `.claude/`).
4. **Only then rotate** credentials, in order: npm → GitHub PATs → cloud keys → SSH keys.

`saw audit` enforces this in its output: whenever it finds credential exposure it leads with this
ordered runbook, and its rotation remediation is phrased as the **last** step with the wiper
warning — never "rotate now". (This is distinct from the GitHub **App** installation-token
auto-rotation in `docs/USAGE.md`, which is a routine hardening feature, not incident response.)

## Config
- `config/security.yml` — targets (local globs + GitHub users/orgs), exclude dirs, remediation mode,
  allowlist, alert routing. `exclude_dirs` defaults already skip `.git`, `node_modules`, build
  output, `.malware-quarantine`, and `reports`.
- The signature database is shipped inside the package
  (`src/stayawake/bots/security/data/signatures.yml`); the installed scanner is self-contained.
  Point at a custom DB by setting `settings.signatures_path` in `config/security.yml`.
- **Allowlist rules require a `signature`** (optionally scoped by `path_glob`). A bare `path_glob`
  is ignored — it would blanket-suppress every signature on that path, so a fresh payload dropped
  there would slip by. The reusable Action takes `path_glob|signature_id` entries.

## CLI / pipeline (terminal-first sinks)

`saw scan` is **terminal-first**: it runs detection in one pass and renders a full human report
(with full evidence) to `stdout`; it **persists nothing by default**, and its exit code **is**
the verdict (`0` clean / `1` infected — no `--fail` flag). Output beyond the terminal is delivered
through a Strategy **sink layer** (`security/sinks/`), each an opt-in flag:

- **terminal** (default) — human report on `stdout`, progress on `stderr`. Full evidence.
- **`--json`** — machine-readable JSON on `stdout`. Full evidence; ephemeral (pipe it).
- **`--sarif FILE`** (`security/sinks/sarif.py`) — SARIF 2.1.0 log for upload to GitHub
  code-scanning (`github/codeql-action/upload-sarif`); findings surface in the Security tab and as
  inline PR annotations. **Evidence is redacted** (fingerprint only). Pure output layer — the gate
  stays the exit code.

  **CI delivery model.** Code-scanning (SARIF upload) needs GitHub Advanced Security on a private
  repo, so it is **owned solely by `security-sentinel.yml`** (the non-gating, post-merge reporter),
  gated by an explicit repo variable **`vars.ENABLE_CODE_SCANNING`**. The **gates** (`worm-guard.yml`,
  `release.yml` self-scan) **never upload** — their check colour is the `saw scan` exit code and
  nothing else, so a SARIF upload issue can never flip a required merge/publish gate red. When
  `ENABLE_CODE_SCANNING` is unset the upload is a **deliberate, labeled skip** (findings still reach
  the run log, the SARIF **build artifact**, and `--alert` issues/Slack); when it is `true` and the
  upload genuinely fails, the **sentinel** job goes red (a red *Upload SARIF* step means "upload
  broken/misconfigured", **not** "worm found"). Set `vars.ENABLE_CODE_SCANNING=true` after enabling
  Advanced Security or making the repo public.
- **`--alert`** — opens/closes a GitHub issue per infected repo and posts a Slack summary in the
  same pass (reads `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `SLACK_WEBHOOK_URL`). Bodies are evidence-free.
- **`-d/--reports-dir DIR`** — opt-in `latest.json` + `latest.md` in `DIR`. **Evidence redacted.**

**Evidence redaction.** Any *persisted* artifact (SARIF, `-d` files) stores a fingerprint
`{sha256, preview (first 24 chars), len}` instead of the raw payload — full evidence only ever
appears on the live terminal (`stdout`/`--json`). In-tree report files were redundant, tamperable,
and re-distributed live malware payloads, so durable records now live **outside the repo tree**:
GitHub code-scanning (SARIF, uploaded not committed), issues + Slack, and CI artifacts. Security
reports are **no longer committed**.

the `security/hygiene/` package backs `saw audit` (local posture + branch-protection; the opt-in
`--verify` delegates a single-directory content-scan to the engine); remediation is `saw fix` (see
[Remediation](#remediation)).

Run via the terse **`saw`** CLI: `saw scan` · `saw fix` · `saw audit` — see the
[CLI guide](CLI.md). The legacy `stayawake-security-*` console scripts have been **removed**;
`saw` is the only local security surface.

## Testing
`tests/bots/security/` — inert fixtures (clean vs infected) covering every matcher, plus a real
evil-merge git fixture. Run (package installed): `python -m unittest discover -s tests`.

## Remediation

`saw fix` — cleanup is delivered as a **pull request**, never an in-place edit (so it can't
corrupt a working tree, and nothing reaches a default branch until a human merges). Scope is
**local by default**; `--remote` sweeps the configured GitHub targets. Each repo's outcome
**streams live** as its PR is opened/updated. Evil-merge findings are reported as manual (need a
history rewrite).

For each infected repo it pushes a stable `security/auto-clean` branch and opens **one rolling
PR**, targeting the default branch for review. Before opening it checks the API for an existing
open PR from that branch and **updates it instead of creating a duplicate**. Work is isolated in
a git worktree; it never commits to or force-pushes the default branch. After applying, it
**re-scans and aborts (no PR) if a confirmed infection is still detected**, discloses any
remaining heuristic/suspicious findings in the PR body, and the commit message / PR body
describe only what was *actually* changed. An injected payload is recovered from git (the
file's last clean committed version), or deferred to manual review with the exact command —
never reconstructed.

`saw audit [--repo owner/name]` checks local posture (cached GitHub credential,
VS Code auto-run / Workspace Trust, host persistence / drop-artifacts) and, with a token +
`--repo`, that the default branch is protected and the **Worm Guard** check is required. Add
`--verify` to content-scan a lone weak host artifact (e.g. `~/.node_modules`) and grade it honestly.

## Prevention

A reusable `worm-scan` composite Action — published to the GitHub Marketplace as
[`Ndevu12/strix`](https://github.com/Ndevu12/strix) (`uses: Ndevu12/strix@v1`), with the in-repo
composite at `.github/actions/worm-scan` kept for this repo's own self-gating and from-source
pins — gates PRs/merges in
any repo (`worm-guard.yml`), portable git hooks (`prevent/hooks/`) block local commits and
catch incoming infections, and `prevent/SECURITY_BASELINE.md` covers branch protection +
token/Action hardening. The Action installs the published scanner (Strix from PyPI; the in-repo
composite via `git+…@<ref>`) rather than cloning the source tree, so the gate runs the same code
as the package. The gate is installed and verified from the CLI by
[`saw guard`](CLI.md#saw-guard): `saw guard setup` writes (or surgically SHA-pin-bumps) the
`worm-guard.yml` — locally to review, or as a rolling PR — and `saw guard check` reports, across a
sweep of repos, whether each gate is present, **SHA-pinned**, current with the latest Strix release,
and **required** by branch protection.

Supply-chain hardening of the gate itself: pin `sentinel-ref` to a **commit SHA** (never `@main`,
which is mutable) and SHA-pin every third-party action — a later compromise of an upstream tag
or of `main` then can't silently change what the gate runs. Bump the pin deliberately after a
reviewed scanner/signature update. The gate scans the whole tree; `reports/**` (the availability
cron's output) is the only exemption — security reports are no longer committed, and any persisted
security artifact is evidence-redacted, so there is no in-tree payload for the gate to re-flag.

A pin is only as good as its freshness, so two guards keep it honest without weakening the
tamper-resistance the pin buys:
- **Capability-assert** (`worm-scan` action): after installing the pinned scanner, the action
  verifies it actually supports the CLI flags the action invokes (e.g. `saw scan --sarif`) and
  fails fast with the fix when the pin is too old — instead of an opaque mid-run argparse error.
- **Drift alarm** (`scanner-pin-drift.yml`): weekly, it compares the pinned SHA's engine subtree
  (`src/stayawake/bots/security/**`) against `main` and opens a self-closing issue when they
  diverge, so a stale pin can't silently run an out-of-date engine. It is subtree-scoped, so the
  `chore(sentinel)` report commits never raise a false alarm. (This is the seam a future
  engine/signatures cadence split builds on: a slow, pinned engine; fast, separately-distributed
  signatures.)

## Trigger model (event-driven, not scheduled)

Uptime monitoring needs polling; **security state only changes when code changes**, so
the security side is event-driven — copying the availability sentinel's cron would be
wasteful and reactive.

| Where | Trigger | What runs |
|-------|---------|-----------|
| Hosted — gate | `pull_request` + `push` (code paths) | `worm-guard` blocks infection from landing (read-only; the exit code is the gate) |
| Hosted — sentinel | `push` to `main` (merge) + `workflow_dispatch` + weekly backstop | scan the repo, then push durable records via `--alert` (issue + Slack) + `--sarif` (code-scanning) + CI artifacts — no report is committed |
| Local — CLI | on demand | `saw scan` over all dev roots (report to the terminal); `saw fix` opens a cleanup PR per infected repo |
| Availability | `schedule` (*/5) | uptime genuinely needs polling — the one place a clock is correct |

Org-wide coverage is **distributed**: every repo runs its own `worm-guard` on its own
events, rather than a central poller sweeping the org on a timer. A weekly backstop catches
newly-added signatures applied to old code.
