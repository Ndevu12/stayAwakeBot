---
description: Create host-level denials on this machine with saw harden. Reports in place only after a read-back.
---

# Harden this machine

[`saw audit`](audit-a-machine.md) reports. [`saw harden`](../reference/cli/harden.md) acts on the
host. It never touches a project's dependency tree — that is [`saw fix`](fix-findings.md).

```bash
saw harden
```

Root is not required. It acts where it can and names anything it did not take.

```bash
sudo saw harden
```

Run it again with `sudo` to act on the rest and to strengthen what is already in place. The result
tells you which controls root holds and which you hold.

A write counts as in place only after it is read back. An unverifiable write is unknown, never
success. Anything already in use is left unchanged — clear it, then run again. If a running process
still holds code that is not on disk, the command refuses until that process is captured.

To remove a control it placed: `chflags nouchg <path>` on macOS or `chattr -i <path>` on Linux,
then `rmdir <path>`, as its owner.

It does not claim that one control protects anything else.
