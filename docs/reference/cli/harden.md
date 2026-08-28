---
description: saw harden — create host-level denials on this machine, and report them as in place only after a read-back.
---

# `saw harden`

Create host-level controls on this machine. It never touches a project's dependency tree — that is
[`saw fix`](fix.md). A write is reported as in place only after it is read back. An unverifiable
write is unknown, never success. The result does not claim that one control protects anything else.

```text
saw harden
```

This command must run as root. If a running process still holds code that is not on disk, it
refuses: capture that process first.

| Exit | Meaning |
| --- | --- |
| `0` | Every target is in place, verified by read-back. |
| `1` | Refused — capture a running process first, or processes could not be examined. |
| `2` | Could not run — not root, or not implemented on this platform. |
| `3` | At least one target is unknown or was already occupied and was not changed. |

See [audit a machine](../../how-to/audit-a-machine.md) for the read-only view of the same host.
