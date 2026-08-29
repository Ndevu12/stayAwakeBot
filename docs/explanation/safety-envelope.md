---
description: What saw is allowed to change and what it will not touch: scan is read-only, fix writes the cleanup branch and, on a confirmed infection, the installed tree in this repository, nothing lands without a merge.
---

# The safety envelope

What `saw` is allowed to change, and what it will not touch. A security tool that damages a working
repository gets uninstalled, so the boundaries are deliberately narrow.

## `scan` is read-only

`saw scan` never modifies a file, anywhere, under any flag. It renders a report and returns a
verdict. Remediation lives in a separate command, on purpose — so no one can trip into it, and so
`scan` is safe to run on anything.

## `fix` writes only to its own branch

`saw fix` prepares the cleanup on a generated `security/auto-clean` branch and stops. Source changes
land on that branch. It does not push or open anything unless you pass `--pr`, and re-running updates
the same rolling pull request instead of opening another. That publish does not overwrite a remote
ref. On a confirmed infection it also removes
the installed tree, generated build outputs, and the lockfile in this repository (the lockfile is
kept on CI). `saw discard` removes only that branch and that PR — never a branch you made.

`saw fix amend` is a separate act: it replaces past commits that still carry the payload and
force-updates each branch they sat on. That force-update is the fix. It does not open a pull
request, it does not take `--branch`, it does not move tags, and `saw discard` does not undo it.
The previous objects remain until collected.

Nothing lands on a protected branch without a human merge. The CI gate follows the same rule: on an
infected verdict it opens the fix as a pull request and stays **red until you merge it**. Remediation
opens the fix; it never makes the check pass. `saw fix amend` is not on that path.

## Fixes are recovered, not reconstructed

A cleaned file comes from git history — the real previous content — or the file is quarantined whole.
`saw` never surgically edits a source file, so a fix cannot corrupt valid code. When a clean version
cannot be proven safe to restore, the finding is deferred to review with the reason, rather than
guessed at.

## Heuristics are never auto-fixed

Anything short of confirmed is disclosed for a person to judge. See
[verdicts](verdicts.md).

## A host is never auto-cleaned

`saw audit` reports; it does not remediate. Deleting a persistence entry on a live host destroys the
evidence and rarely removes the cause, and deleting a credential you actually use is an outage rather
than a fix. So the audit tells you what it found and what to do in which order, and leaves the
machine alone. See [audit a machine](../how-to/audit-a-machine.md).

## Reports do not carry payloads

Full evidence stays on your terminal or in `--json`. Anything persisted stores a fingerprint instead,
and alert bodies carry no evidence at all — a security report can never re-distribute live malware.
See [report sinks](../reference/cli/sinks.md).
