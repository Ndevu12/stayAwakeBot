# StayAwakeBot — Security Sentinel Architecture

A worm-hunting / auto-fixing / preventing subsystem that reuses the bot's proven
`gather → report → alert → commit` pipeline. Built data-driven and layered so new
threats are added as configuration, not code.

## Pillars
- **Detect** — scan local & remote repos for known indicators (IoCs) and evil merges.
- **Report/Alert** — JSON + markdown + badge; Slack + GitHub issues (Phase 2).
- **Auto-fix** — quarantine/strip via PRs, never force-push (Phase 3, dry-run default).
- **Prevent** — reusable CI gate + pre-commit + CI-token hardening (Phase 4).

## Layers (SRP)
```
config (data) ─► signature engine ─► matchers ─► findings ─► scanner ─► report/alert ─► remediator(PR)
```
- **Signatures** (`config/security_signatures.yml`): IoCs as data. New threat = new entry.
- **Matchers** (`stayawakebot/security/matchers/`, Strategy): one technique each, selected by a
  signature's `matcher` field — `content`, `filename`, `structural-json`, `heuristic`, `git-history`.
- **Targets** (`stayawakebot/security/targets/`, DIP): `LocalRepoTarget` and `RemoteRepoTarget`
  (sandboxed shallow clone, read-only) share one interface.
- **Scanner** (`stayawakebot/security/scanner.py`): runs matchers over a target → `ScanResult`; applies allowlist.
- **Findings** (`stayawakebot/security/models.py`): typed `Severity`/`Finding`/`ScanResult`.
- **Shared** (`stayawakebot/common + stayawakebot/adapters`): reused by both subtasks (DRY).

## Safety / threat model
- **Never executes scanned code** — static analysis + git plumbing only.
- Remote targets cloned into ephemeral sandboxes (`core.hooksPath=/dev/null`, no prompts), removed after.
- Remediation (Phase 3) defaults to **report-only**; fixes go through **PRs**, never force-push to main.
- The bot's `contents: write` token is high-value — Phase 4 scopes it and hardens the auto-commit step
  (this is the exact surface the worm used to inject `2fc2e43`).

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
- `config/security_signatures.yml` — the signature database.

## CLI / pipeline scripts
- `stayawakebot/cli/security_scan.py (+ security/service.py)` — Phase 1 (detect → `reports/security/latest.json` + `latest.md`).
- (Phase 2) `security_report.py` / `security_alert.py`; (Phase 3) `security_remediate.py`.

## Phasing
1. **Detect (this PR)** — engine + matchers + scanner CLI + tests.
2. **Alert** — Slack/issues + security badge + scheduled `security-sentinel.yml`.
3. **Auto-fix** — `remediator` (dry-run → PR) + history-purge helper.
4. **Prevent** — composite `worm-scan` Action + pre-commit + CI hardening.

## Testing
`tests/security/` — inert fixtures (clean vs infected) covering every matcher, plus a real
evil-merge git fixture. Run: `python -m unittest discover -s tests/security`.

## Remediation (Phase 3)

`python -m stayawakebot.cli.security_remediate [--apply]` — dry-run by default. With
`--apply` it strips/quarantines worm artifacts (originals backed up to `.malware-quarantine/`)
and commits the fix to a `security/auto-clean-<stamp>` branch — never main, never force-pushed.
Evil-merge findings are reported as manual (need a history rewrite).
