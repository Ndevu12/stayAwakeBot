# Worm Prevention Baseline

How to stop the self-propagating worm from re-entering a repository. Apply per repo
(or org-wide). Layered: pre-commit (local) → CI gate (PR/merge) → branch protection.

## 1. CI gate (blocks infected merges — the key control)
Add the reusable scan to any repo's CI; it fails the check on worm indicators or
evil merges (changes present in a merge but neither parent — the worm's stealth vector):

```yaml
# .github/workflows/worm-guard.yml
name: Worm Guard
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  worm-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # full history for evil-merge detection
      - uses: Ndevu12/stayAwakeBot/.github/actions/worm-scan@<PIN-A-SHA>
        with: { fail-on-findings: 'true' }
```
**Pin `@<SHA>`**, not `@main`, so a compromise of the action repo can't change what runs.

## 2. Pre-commit hook (local first line)
```bash
bash <path-to-stayAwakeBot>/prevent/install-hooks.sh   # in each repo
```
Blocks committing loader fingerprints, fake `fa-solid-400.woff2`, `.vscode` folderOpen
auto-run tasks, and `.gitignore` worm markers. Bypass a false positive with `--no-verify`.

## 3. Branch protection (defense in depth)
- Require pull-request review before merging to `main`; **disable auto-merge**.
- Require the **Worm Guard** status check to pass.
- Restrict who can push to `main`; require linear history (blocks surprise merge commits).

## 4. Token & Action hardening
- Pin all third-party actions to a **commit SHA**, not a tag.
- Give workflow tokens the **least privilege** they need (`contents: read` for the gate;
  only the report-committing jobs get `contents: write`).
- Rotate the bot's `contents: write` token periodically; scope `GH_SECURITY_TOKEN`
  to read-only repo access for cross-repo scanning.
- Turn off Settings Sync for editor configs you don't control, and disable VS Code
  automatic tasks: `"task.allowAutomaticTasks": false` + enable Workspace Trust.

## 5. Recovery
If the gate flags a repo, clean it:
```bash
python -m stayawakebot.cli.security_remediate --apply   # dry-run first (omit --apply)
```
Evil merges already in history need a `git filter-repo` purge + force-push after everyone
on the team has cleaned their machines.
