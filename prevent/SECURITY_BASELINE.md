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

## 2. Local git hooks (defense-in-depth on the developer machine)
The hooks are dependency-free (grep only) and cover both directions:
- **`pre-commit`** — blocks *committing* loader fingerprints, fake `fa-solid-400.woff2`,
  `.vscode` folderOpen auto-run tasks, and `.gitignore` worm markers (bypass with `--no-verify`).
- **`post-merge` / `post-checkout`** — scan code that *arrives* via `git pull`/merge or a
  fresh clone/branch switch, and warn. This is the layer that catches **evil merges**
  (the worm's real spread vector), which a pre-commit hook cannot see.

```bash
bash <stayAwakeBot>/prevent/install-hooks.sh                 # this repo
bash <stayAwakeBot>/prevent/install-hooks.sh --template      # all FUTURE clones (init.templateDir)
bash <stayAwakeBot>/prevent/install-hooks.sh --all ~/dev ~/work   # every existing repo under roots
```

Also audit the machine's posture (cached GitHub credential, VS Code auto-run / Workspace Trust):
```bash
stayawake-security-audit            # advisory; add --fail-on-issues for scripts/CI
```

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
stayawake-security-remediate --apply   # dry-run first (omit --apply)
```
Evil merges already in history need a `git filter-repo` purge + force-push after everyone
on the team has cleaned their machines.
