# Incident & Remediation: worm payload purged from stale branches

**Date of remediation:** 2026-06-29
**Date payload introduced:** 2026-05-26
**Status:** Branches deleted from `origin` and locally. `main` was already clean.

## Summary

A self-propagating worm payload was committed to this repository on 2026-05-26 under
the automated bot identity `StayAwakeBot Sentinel <bot@stayawake.local>`, in commit:

```
2fc2e435ec76d131c773080bc0716e50a631ec9e
chore(sentinel): availability report 2026-05-26 19:25 UTC
```

The commit message carried **no test marker** and the `bot@stayawake.local` identity is
merely the bot's default local git identity — neither indicates the change was benign.
The commit bundled a routine availability report and a genuine FontAwesome font set
together with a deliberately constructed execution chain.

## The payload (what made it malicious)

1. **Disguised executable — `public/fonts/fa-solid-400.woff2`**
   Not a font. A 5,533-byte obfuscated JavaScript file that hijacks the Node module
   loader (`global[...] = require; global[...] = module`) behind a string-shuffling
   deobfuscator. Its siblings (`fa-solid-900.woff2`, etc.) are genuine WOFF2 binaries;
   this one was plain text named to blend into the font set.

2. **Trigger — `.vscode/tasks.json`**
   A task labelled `eslint-check` with `"runOn": "folderOpen"` running
   `node ./public/fonts/fa-solid-400.woff2`, silenced with
   `"hide": true`, `"reveal": "never"`, `"echo": false`, `"close": true`.

3. **Enabler — `.vscode/settings.json`**
   `"task.allowAutomaticTasks": true` (run the folderOpen task with no prompt) plus
   `"terminal.integrated.hideOnStartup": "always"` (hide the terminal it runs in).

Opening the folder in VS Code would silently execute the obfuscated payload. The bot
may have been an unwitting courier that swept the files into an auto-commit, but the
disguise-and-autorun wiring is deliberately authored, not accidental.

## Remediation

`main` and the active development lineage never contained `2fc2e43` (the PRs that carried
it were squash-merged, so their net — verified worm-free — changes landed on `main` while
the original branch tips retained the infected history). The payload survived only in the
history of stale/merged side branches, which were deleted.

### Branches deleted (pre-deletion tip SHAs, for recovery)

| Branch | Backing PR | Pre-deletion tip SHA |
| --- | --- | --- |
| `chore/protect-history-and-ci-safeguards` | #4 (merged) | `2fc2e435ec76d131c773080bc0716e50a631ec9e` |
| `chore/rebrand` | #2 (merged) | `2fc2e435ec76d131c773080bc0716e50a631ec9e` |
| `copilot/improve-ci-reporting-safety` | #3 (closed, WIP) | `2fc2e435ec76d131c773080bc0716e50a631ec9e` |
| `feat/security-detect` | #965 (merged) | `00a1d0c9f2354e9650b8b44c8dc0eab8ab70f085` |
| `refactor/split-helpers` | #1 (merged) | `797c9fdd6a7d5ef7f690ea6623585648225335e8` |
| `security/remove-worm` | #964 (merged) | `832443b8e30cbadf571a2f4a7e20853e02566ba6` |
| `fix/readme-badge-blank-line-and-architecture` | #927 (merged) | `b4f3de3c823ceeb0e24f31e89f35f8e0f1eee9bf` |

The infected introduction commit is `2fc2e43`; the in-tree removal commit (on the old
`security/remove-worm` lineage) was `832443b`.

## Required GitHub-side follow-ups

Deleting the branches removes the refs, but does **not** by itself erase the objects from
GitHub:

- Commit `2fc2e43` remains reachable **by its SHA** until GitHub garbage-collects. To force
  this server-side, delete the branches (done) and then ask GitHub Support to run GC on the
  repository.
- The commit persists in any **forks** and in **pull-request refs** (`refs/pull/<n>/head`).
  Audit forks and, where possible, close/expire the affected PR refs.
- This payload executes code rather than exfiltrating a stored secret, but if any credential
  was ever present in an environment where the autorun could have fired, rotate it.

## Prevention (already in place)

See [`SECURITY_BASELINE.md`](./SECURITY_BASELINE.md) — CI worm-guard gate, local git hooks,
and branch protection are the layered controls that block re-entry.
