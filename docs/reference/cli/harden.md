---
description: saw harden — create host-level denials on this machine, and report them as in place only after a read-back.
---

# `saw harden`

Create host-level controls on this machine. It never touches a project's dependency tree — that is
[`saw fix`](fix.md). A write is reported as in place only after it is read back. An unverifiable
write is unknown, never success. The result does not claim that one control protects anything else.

```text
saw harden
sudo saw harden
```

Root is not required. Run it as yourself and it acts where it can; anything it did not take is
named in the result, and left exactly as it stood.

Run it again with `sudo` to act on the rest and to strengthen what is already in place. The result
distinguishes a control root holds from one you hold, and tells you which you have.

If a running process still holds code that is not on disk, it refuses: capture that process first.
If it could not examine what is running on this machine, it refuses as well. Neither depends on
whether you gave it root.

Anything already in use is left unchanged.

See [audit a machine](../../how-to/audit-a-machine.md) for the read-only view of the same host.
