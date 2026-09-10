---
description: saw watch — keep this machine checking itself, ending running code the tool has identified.
---

# `saw watch`

Ask this machine to keep checking itself. From then on, and from every login, it makes a pass over
what is running and ends code the tool has **identified**. It never asks for a password, and it
writes what it saw to its own record so a later pass can tell something that has come back from
something new. It keeps checking until you stop it.

```text
saw watch
saw watch status
saw watch stop
```

It is deliberately narrower than [`saw harden`](harden.md). Harden runs with you present: it ends
everything it grades, and it can ask for privilege to reach what it otherwise could not. This one is
built to run with nobody watching, so it holds a higher bar before it ends anything, and it leaves
the rest for you.

## What it will and will not end

| | |
| --- | --- |
| Code the tool has identified | ended |
| Code that only *looks* wrong | left alone, and recorded |
| Anything needing a password | left alone — it will not prompt where nobody can answer |

Whatever it declines is not forgotten. Run [`saw harden`](harden.md) when you are at the machine and
it will act on what this pass would not.

## What it tells you

One line about where this machine stands:

- nothing is running code it should not;
- code was running and has been stopped;
- something that was stopped here before is running again — which is the sentence that matters, and
  the point at which to take the machine off the network;
- something is running that this machine cannot identify;
- something could not be stopped.

It names no paths and no process numbers. If a pass could not finish what it started, it says so
rather than reporting a clean machine.

## When it runs by itself

[`saw harden`](harden.md) puts this in place as part of hardening a machine, and `saw watch` is how
you ask for it on its own, check it, or change your mind about it.

`saw watch` asks this machine to keep making the pass — starting with your session, and started
again if it ever stops, so the machine is not left unwatched. It says whether that is in force now
or from your next login; where the system will not start it immediately, the arrangement is still
made and takes effect then. It keeps doing that until `saw watch stop`.
Asking twice changes nothing and says so.

It is asked for by name rather than arranged by [`saw harden`](harden.md), because a process that
keeps running and ends things is a larger thing to agree to than the controls harden places, and it
should not arrive as a side effect of something else.

What it runs is fixed. There is nothing in it to configure, and therefore nothing in it for anyone
else to point somewhere else; if it is not exactly what `saw` wrote, running `saw watch` again puts it
back and tells you it had been changed. Anything else found under that name is left alone —
stopping removes saw's own work and nothing else.

A quiet pass says nothing. Only a pass that found something speaks.

## The record

The pass keeps a small record under your state directory of the code it has seen: when each was
first and last seen, how often, and whether it was ended. That is what lets it say *again* rather
than repeating the same alarm every pass.

The record holds no code — the payload itself is never written to it, because a command line can
carry your own secrets and that file outlives the run. Deleting the record costs nothing but the
history: the next pass still examines every process on its own evidence, so nothing can be hidden
from this command by editing or removing it.

## Platforms

macOS and Linux. On macOS it is a login item; on Linux, a user service. Either way it starts with
your session and is started again if it stops, and `saw watch stop` removes it.

Elsewhere the command says it could not arrange it, rather than reporting a machine as watched.

## See also

- [`saw harden`](harden.md) — the same job with you present, and able to ask for privilege
- [`saw audit`](audit.md) — what else this machine looks like

`saw watch status` says whether this machine is checking itself. Whether it is running is asked
of the system, not read from the file: one command stops the check without changing a byte.

It is set up from the copy of saw you run it with, so run it from an installed one. A copy inside a temporary directory is refused: the check would work until that directory is cleaned up. If the check ever stops, `saw audit` says so.
