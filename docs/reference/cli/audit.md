---
description: saw audit — check the machine for credential exposure, editor auto-run and host persistence, and whether credential rotation is safe.
---

# `saw audit`

Audit the machine: credential exposure, editor settings for every editor of the VS Code family installed here, what a coding agent may run without asking, the start-up surface, and optionally a
repository's branch protection and rulesets. Every run ends with a **rotation-safety verdict**. See [audit a
machine](../../how-to/audit-a-machine.md) for what to do with each outcome. Scope: [what a clean
audit does and does not
mean](../../how-to/audit-a-machine.md#what-a-clean-audit-does-and-does-not-mean).

```text
saw audit [--repo OWNER/NAME] [-b BRANCH] [-f] [--verify] [--no-stream]
```

| Option | Description |
| --- | --- |
| `--repo OWNER/NAME` | Also audit that repository's branch protection and rulesets (needs a token). |
| `-b`, `--branch NAME` | Branch whose protection is checked (default: `main`). |
| `-f`, `--fail` | Fail the run on a weaker warning-level hygiene issue, and when `--repo` could not check whether the branch requires the worm gate. The rotation-safety axis gates unconditionally, independent of this flag. |
| `--verify` | **Opt-in:** content-scan a suspicious directory the audit flagged outside a repository and say what it found: malicious code, clean, or not cleared. A directory that is not cleared is never reported clean, and the audit then does not say that changing credentials is safe. It examines that one directory and never changes how `saw scan` behaves. |
