---
description: Put saw's controls in place on this machine with saw harden.
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

When saw is installed in a virtual environment or with pipx, `sudo` does not find it by name. Run
the command the result gives you: it names the saw you ran by its full path.

A write counts as in place only after it is read back. An unverifiable write is unknown, never
success. Something already where a control goes is moved aside so the control can be placed; a known
worm's staging kit there is deleted instead. If a running process
still holds code that is not on disk, the command refuses until that process is captured.

To remove the controls it placed:

```bash
saw harden --take-back
```

It removes only what it placed, puts back what it moved aside, and reports anything it did not. Add `sudo` for the ones root
holds.

It does not claim that one control protects anything else.
