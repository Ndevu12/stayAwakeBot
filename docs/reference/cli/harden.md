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

See [audit a machine](../../how-to/audit-a-machine.md) for the read-only view of the same host.
