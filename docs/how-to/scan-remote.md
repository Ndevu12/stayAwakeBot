---
description: Scan GitHub repositories with saw — a single repo, a user, or a whole organisation — and how targets are resolved.
---

# Scan GitHub repositories

Scanning is local unless you say otherwise. `--remote` (and `--user`/`--org`, which imply it) clones
GitHub repositories instead. One scope per run.

```bash
saw scan --remote                 # configured targets, else your own repositories
saw scan --org UB-TechDEV         # a whole organisation
saw scan --remote Ndevu12/strix   # one repository
saw scan --org UB-TechDEV -j 8    # eight at a time
```

## Authenticate first

Public repositories need nothing. For private ones, and for anything that writes, set up a
credential: `gh auth login` on a workstation, `GH_SECURITY_TOKEN` in CI, or a GitHub App for
continuous org-wide use. Check what you have and what it can do:

```bash
saw auth status
```

It names exactly what is missing and the command that fixes it. The resolution order and the least
privilege each command needs are in [credentials](../reference/cli/credentials.md).

## Which repositories get scanned

First match wins: ad-hoc `--user`/`--org`/`owner/repo` selectors, then configured
`targets.github`, then the repositories you own (or the ones a GitHub App installation can see). The
full ladder is in [remote targeting](../reference/cli/remote.md).

The same ladder applies to `saw fix --remote`, `saw discard --remote` and `saw guard --remote`.

Next: [fix findings](fix-findings.md) · [gate CI](gate-ci.md)
