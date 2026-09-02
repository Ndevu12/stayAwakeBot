---
description: saw audit — check the machine for credential exposure, editor auto-run and host persistence, and whether credential rotation is safe.
---

# `saw audit`

Audit the machine: credential exposure, editor settings, the start-up surface, and optionally a
repository's branch protection. Every run ends with a **rotation-safety verdict**. See [audit a
machine](../../how-to/audit-a-machine.md) for what to do with each outcome. Scope: [what a clean
audit does and does not
mean](../../how-to/audit-a-machine.md#what-a-clean-audit-does-and-does-not-mean).

```text
saw audit [--repo OWNER/NAME] [-b BRANCH] [-f] [--verify] [--no-stream]
```

| Option | Description |
| --- | --- |
| `--repo OWNER/NAME` | Also audit that repository's branch protection (needs a token). |
| `-b`, `--branch NAME` | Branch whose protection is checked (default: `main`). |
| `-f`, `--fail` | Fail the run on a weaker warning-level hygiene issue. The rotation-safety axis gates unconditionally, independent of this flag. |
| `--verify` | **Opt-in:** content-scan a suspicious directory the audit flagged outside a repository (for example a `~/.node_modules`) and report what it found — worm markers, scanned clean, an honest "too large / unreadable, verify it yourself", or that the scan did not clear it and why. Only a scan that read the whole directory and found no markers clears it; anything less is never reported as one that found nothing, and it withholds the rotation all-clear. It examines that one directory and never changes how `saw scan` behaves. |
