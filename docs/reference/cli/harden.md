---
description: saw harden — put saw's controls in place on this machine, and take them back.
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

When saw is installed where `sudo` does not look, such as a virtual environment or pipx, the
command saw gives you names it by its full path.

It also puts [`saw watch`](watch.md) in place, which ends code saw has identified from then on and
after every login — the same arrangement that command makes. `--take-back` removes it with the
rest.

The first line of the result says where this machine stands: code that is still running, controls
that are not in place, or every control in place. Each line after it names the command that acts on
what it reports.

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

When stopping code needs root, your system asks you for permission with its own prompt; saw never
asks for or sees your password. This happens only when your account administers this machine.

If a running process still holds code that is not on disk, it refuses: capture that process first.
If it could not examine what is running on this machine, it refuses as well. Neither depends on
whether you gave it root.

Where something is already where a control goes, it is moved aside, beside where it was, and the control
is placed. A known worm's staging kit there is deleted instead, and only the facts about it are kept.
Where only an administrator can do this, the result says to run it again with sudo.

When something where saw's git hooks run is not what saw installed, the result says so and
names it. This command does not touch hooks; [`saw hook repair`](hook.md) puts them back.

`--take-back` removes the controls this command placed, puts back what it moved aside (never a
staging kit), and reports anything it did not remove or put back.

See [audit a machine](../../how-to/audit-a-machine.md) for the read-only view of the same host.
