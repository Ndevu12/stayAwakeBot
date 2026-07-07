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
matcher parses `package.json` and the npm / yarn / pnpm lockfiles and flags any dependency — direct
**or** lockfile-transitive — whose exact `name@version` is on a **data-driven known-bad blocklist**
(the `malicious-dependency` signature's `known_bad` list in `signatures.yml`). An exact match is
decisive → **confirmed** (INFECTED).

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
  degrade the verdict to "has any known CVE" and bury real worm signal. So CVEs are an **opt-in
  advisory tier** (`saw scan --advisories` / config `dependency_advisories: true`, off by default):
  reported in their own section, routed out of the verdict (`ScanResult.advisories`, `advisory_only`
  findings), and they never change the exit code. Malware is classified by structured signals only
  (`MAL-` id/alias, `database_specific.type == malware`, CWE-506) — never free text.
- **Decisions / residuals (deliberate):**
  - A `package.json` **version range** (`^4.2.11`) is ambiguous — it may or may not resolve to the
    bad version — so ranges are **not** matched; the lockfile's resolved version is the source of
    truth. A range-only project with no lockfile is a documented residual.
  - **Scanning `node_modules` content behaviorally is deferred** (off by default) — it is expensive
    and noisy, and the lockfile audit already names exactly what is installed. The behavioral engine
    covers a payload that reaches the *repo tree*; installed dependency *content* is out of scope by
    default.
  - Lockfiles are read **whole** (up to 32 MB, bypassing the scan's head/tail truncation so a large
    `package-lock.json` still parses); a pathological lockfile beyond that cap, and an aliased
    dependency in a *yarn/pnpm* lockfile (npm aliases are resolved via the lockfile's `name` field),
    are residuals.
  - The dynamic corpus matches on an advisory's **explicit affected-version list** only; advisories
    that encode affected **ranges** are deferred to the per-ecosystem version-range comparators
    (later phase). Cache **snapshot pinning + signature/checksum verification** (against a poisoned
    feed) and the global-vs-repo-pinned cache location are deferred to the trust-hardening phase; a
    stale/unverified cache is a documented residual until then. The engine is architected as a
    resolver → store → matcher spine (`bots/security/dependencies/`) so more ecosystems (PyPI, Go,
    Rust, …) become new resolvers without touching the matcher.

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

`security/hygiene.py` backs `saw audit` (local posture + branch-protection); remediation is
`saw fix` (see [Remediation](#remediation)).

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
VS Code auto-run / Workspace Trust) and, with a token + `--repo`, that the default branch is
protected and the **Worm Guard** check is required.

## Prevention

A reusable `worm-scan` composite Action — published to the GitHub Marketplace as
[`Ndevu12/strix`](https://github.com/Ndevu12/strix) (`uses: Ndevu12/strix@v1`), with the in-repo
composite at `.github/actions/worm-scan` kept for this repo's own self-gating and from-source
pins — gates PRs/merges in
any repo (`worm-guard.yml`), portable git hooks (`prevent/hooks/`) block local commits and
catch incoming infections, and `prevent/SECURITY_BASELINE.md` covers branch protection +
token/Action hardening. The Action installs the published scanner (Strix from PyPI; the in-repo
composite via `git+…@<ref>`) rather than cloning the source tree, so the gate runs the same code
as the package.

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
