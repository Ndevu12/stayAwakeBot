---
description: What each saw exit code means. The exit code is the contract a CI gate reads: clean, infected, unscannable, or rotation-unsafe.
---

# Exit codes

The exit code is the contract. For **`saw scan` it is the verdict, unconditionally** — there is no
`--fail` flag and nothing to parse.

| Code | Meaning |
| --- | --- |
| `0` | Clean. `saw scan`: no target is infected. `saw audit`: the start-up surface was established and is clean, and no weaker warning gated — rotation is safe. `saw harden`: every target is in place, verified by read-back. `saw guard check`: every gate is present, pinned, current and required (or issues were found without `-f`); `saw guard setup`: every repository succeeded or was already current. |
| `1` | `saw scan`: at least one target is **infected**. `saw audit`: a weaker warning-level hygiene issue **and** `-f` was set. `saw harden`: refused because a running process still holds code that is not on disk, or processes could not be examined. `saw guard check`: a gate is absent, unpinned, stale or not required **and** `-f` was set; `saw guard setup`: a repository errored, or a PR could not be opened. |
| `2` | Usage error (unknown command, bad option, a missing explicit `--config` path), **or** a run that could not complete — a malformed config, or a target that errored while being scanned. A target `saw` could not scan is never reported as clean. `saw audit` exits `2` when a check could not run: its own self-test failed, or it stopped with an error. A check that did not answer has not established the surface it covers, so its quiet is not a clean result. `saw harden` exits `2` when it is not root, or the platform is not covered. `saw guard setup` also exits `2` when it cannot resolve the release SHA (offline → pass `--ref`). |
| `3` | **`saw audit` — rotation unsafe.** Either something was found running at start-up, or the start-up surface could not be established — including because a check that reads it could not run. It gates independently of `-f`, because rotating a credential on a compromised host hands over the new one. It outranks `2`: a hazard in what was found is more urgent than a gap in what was covered. See [audit a machine](../how-to/audit-a-machine.md). **`saw harden` — at least one target is unknown or was occupied and left unchanged.** |

`saw guard drift` reports as an issue and always exits `0`, so it is safe on a schedule.

**Migrating to `3`.** It is additive. Code that treats "`0` is fine, non-zero needs attention" is
already correct and fails safe; only code that specifically distinguished `saw audit`'s `1` from its
`2` needs to handle it. `saw scan` and `saw guard` never return `3`.

Why an unscannable target is an error and not a pass: [fail closed](../explanation/fail-closed.md).
