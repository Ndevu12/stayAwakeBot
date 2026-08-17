# The safety envelope

What `saw` is allowed to change, and what it will not touch. A security tool that damages a working
repository gets uninstalled, so the boundaries are deliberately narrow.

## `scan` is read-only

`saw scan` never modifies a file, anywhere, under any flag. It renders a report and returns a
verdict. Remediation lives in a separate command, on purpose — so no one can trip into it, and so
`scan` is safe to run on anything.

## `fix` writes only to its own branch

`saw fix` prepares the cleanup on a generated `security/auto-clean` branch and stops. It does not
touch your working tree, push, or open anything unless you pass `--pr`, and re-running updates the
same rolling pull request instead of opening another. `saw discard` removes only that branch and that
PR — never a branch you made.

Nothing lands without a human merge. The CI gate follows the same rule: on an infected verdict it
opens the fix as a pull request and stays **red until you merge it**. Remediation opens the fix; it
never makes the check pass.

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
