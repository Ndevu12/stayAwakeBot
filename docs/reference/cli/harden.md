---
description: saw harden — create host-level denials on this machine, and report them as in place only after a read-back.
---

# `saw harden`

Create host-level controls on this machine. It never touches a project's dependency tree — that is
[`saw fix`](fix.md). A write is reported as in place only after it is read back. An unverifiable
write is unknown, never success. The result does not claim that one control protects anything else.

```text
saw harden [--no-stream]
sudo saw harden
saw harden --take-back [--no-stream]
```

It also asks this machine to keep checking itself, by putting [`saw watch`](watch.md) in place — the
same arrangement that command makes, made here as part of hardening. `--take-back` removes it with
the rest.

It corrects the editor settings that let a folder run code when it is opened, in **every** editor of
the VS Code family on this machine — Cursor, Windsurf, VSCodium and the rest, not only VS Code
itself.

It also turns off dangerous command auto-approval for chat and agent tools. A blanket "approve
everything", a pattern that matches every command, and each risky command named in the audit are
set to off. Commands you allowed that are not dangerous are left exactly as they are, so what you
chose deliberately keeps working.

It does the same for the coding agents on this machine. Claude Code, the Cursor agent and Codex
each keep a list of what they may run without asking; a risky entry is taken out, and an agent whose
approval step is off is made to ask again. What you allowed that is not risky stays as it is.

`--take-back` restores what had a value before; a setting saw added is left in place and named.

Root is not required. Run it as yourself and it acts where it can; anything it did not take is
named in the result, and left exactly as it stood.

Run it again with `sudo` to act on the rest and to strengthen what is already in place. The result
distinguishes a control root holds from one you hold, and tells you which you have.

If a running process still holds code that is not on disk, it refuses: capture that process first.
If it could not examine what is running on this machine, it refuses as well. Neither depends on
whether you gave it root.

Anything already in use is left unchanged.

When something where saw's git hooks run is not what saw installed, the result says so and
names it. This command does not touch hooks; [`saw hook repair`](hook.md) puts them back.

`--take-back` removes the controls this command placed, and reports anything it did not remove.

See [audit a machine](../../how-to/audit-a-machine.md) for the read-only view of the same host.
