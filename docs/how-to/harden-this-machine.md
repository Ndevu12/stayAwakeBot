---
description: Create host-level denials on this machine with saw harden. Reports in place only after a read-back.
---

# Harden this machine

[`saw audit`](audit-a-machine.md) reports. [`saw harden`](../reference/cli/harden.md) acts on the
host. It never touches a project's dependency tree — that is [`saw fix`](fix-findings.md).

```bash
sudo saw harden
```

A write counts as in place only after it is read back. An unverifiable write is unknown, never
success. If a target already has something in it, it is left unchanged — clear it, then run again.
If a running process still holds code that is not on disk, the command refuses until that process
is captured.

It does not claim that one control protects anything else.
