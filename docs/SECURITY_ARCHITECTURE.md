# StayAwakeBot — Security Sentinel Architecture

A worm-hunting / auto-fixing / preventing bot that reuses the toolkit's proven
`gather → report → alert → commit` pipeline. Built data-driven and layered so new
threats are added as configuration, not code.

## Pillars
- **Detect** — scan local & remote repos for known indicators (IoCs) and evil merges.
- **Report/Alert** — JSON + markdown + badge; Slack + GitHub issues.
- **Auto-fix** — quarantine/strip via PRs, never force-push (dry-run by default).
- **Prevent** — reusable CI gate + pre-commit + CI-token hardening.

## Layers (SRP)
```
signatures (data) ─► signature engine ─► matchers ─► findings ─► scanner ─► report/alert ─► remediator(PR)
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
- The bot's `contents: write` token is high-value — the prevention layer scopes it and hardens the
  auto-commit step (this is the exact surface the worm used to inject its payload via an evil merge).

## Detected vectors (from the live incident)
1. Obfuscated loader in `postcss.config.*` (content + oversized-line heuristic)
2. Fake font payload `public/fonts/fa-solid-400.woff2` (filename + text-in-fontfile heuristic)
3. Camouflage `public/fonts/` dir with "Blockchain Explorer" README (content/heuristic)
4. VS Code `folderOpen` auto-run task running a font via node (structural-json)
5. `.gitignore` worm markers (content)
6. **Evil merges** — content present in neither parent (git-history)

## Config
- `config/security.yml` — targets (local globs + GitHub users/orgs), exclude dirs, remediation mode,
  allowlist, alert routing.
- The signature database is shipped inside the package
  (`src/stayawake/bots/security/data/signatures.yml`); the installed scanner is self-contained.
  Point at a custom DB by setting `settings.signatures_path` in `config/security.yml`.

## CLI / pipeline scripts
- `security/cli/scan.py` (+ `security/service.py`) — detect → `reports/security/latest.json` + `latest.md`.
- `security/cli/report.py` · `security/cli/alert.py` · `security/cli/remediate.py` — report, alert, remediate.

Installed as console scripts: `stayawake-security-scan` · `-report` · `-alert` · `-remediate`
(or `python -m stayawake.bots.security.cli.<action>`).

## Testing
`tests/bots/security/` — inert fixtures (clean vs infected) covering every matcher, plus a real
evil-merge git fixture. Run (package installed): `python -m unittest discover -s tests`.

## Remediation

`stayawake-security-remediate [--apply]` — dry-run by default. With
`--apply` it strips/quarantines worm artifacts (originals backed up to `.malware-quarantine/`)
and commits the fix to a `security/auto-clean-<stamp>` branch — never main, never force-pushed.
Evil-merge findings are reported as manual (need a history rewrite).

`--apply --open-pr` pushes a stable `security/auto-clean` branch and opens **one rolling
PR per repo**, targeting the default branch for review. Before opening it checks the API for
an existing open PR from that branch and updates it instead of creating a duplicate. Work is
isolated in a git worktree; it never commits to or force-pushes the default branch.

## Prevention

A reusable `worm-scan` composite Action (`.github/actions/worm-scan`) gates PRs/merges in
any repo (`worm-guard.yml`), a portable `prevent/pre-commit` hook blocks local commits,
and `prevent/SECURITY_BASELINE.md` covers branch protection + token/Action hardening.
The Action installs the published scanner (`pip install "stayawake @ git+…@<ref>"`) rather
than cloning, so the gate runs the same code as the package.

## Trigger model (event-driven, not scheduled)

Uptime monitoring needs polling; **security state only changes when code changes**, so
the security side is event-driven — copying the availability sentinel's cron would be
wasteful and reactive.

| Where | Trigger | What runs |
|-------|---------|-----------|
| Hosted — gate | `pull_request` + `push` (code paths) | `worm-guard` blocks infection from landing (read-only, fail-on-findings) |
| Hosted — sentinel | `push` to `main` (merge) + `workflow_dispatch` + weekly backstop | scan the repo, refresh badge/status, alert, commit report |
| Local — CLI | on demand | `stayawake-security-scan` over all dev roots; `stayawake-security-remediate [--apply] [--open-pr]` fixes each repo |
| Availability | `schedule` (*/5) | uptime genuinely needs polling — the one place a clock is correct |

Org-wide coverage is **distributed**: every repo runs its own `worm-guard` on its own
events, rather than a central poller sweeping the org on a timer. A weekly backstop catches
newly-added signatures applied to old code.
