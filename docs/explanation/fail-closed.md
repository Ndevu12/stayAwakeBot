---
description: Why a target saw could not scan is never reported as clean, and where that rule shows up across the commands.
---

# Fail closed

**A target that could not be scanned never reads as clean.**

Silence has two causes — there was nothing to find, or nothing was looked at — and only one of them
is good news. Wherever `saw` cannot tell the two apart, it says so and exits non-zero rather than
returning the comfortable answer.

In practice:

- A file that cannot be read, a clone that failed, a malformed config, a worker that died mid-scan —
  each ends the run at [exit `2`](../reference/exit-codes.md), never `0`.
- A scan-on-clone hook that hits its time budget reports the tree as **unverified**, not clean.
- `saw audit` withholds the all-clear when the start-up surface could not be established, and says
  which locations it could not account for.
- `saw guard setup` refuses to write a workflow it cannot pin to an exact commit, rather than
  installing an unpinned gate.
- `saw scan --require-db` turns a missing advisory corpus into a failure, for jobs that must not lose
  coverage quietly.

Where a check is not certain, `saw` warns loudly rather than degrading in silence. Warning noise is
recoverable; a false all-clear is not.

## Why the exit code is the contract

`saw scan` has no `--fail` flag. The verdict *is* the exit status, unconditionally, so a CI gate is
one line with nothing to configure and no way to accidentally configure it away. The same property
makes the failure modes safe: an unscannable target and an infected one both come back non-zero, so a
gate that only ever checks "did this pass" already handles both.

The one deliberate default in the other direction is the advisory corpus: without it a scan continues
with less advisory coverage instead of failing, because advisories never gate anyway. `--require-db`
makes it strict when you need that.
