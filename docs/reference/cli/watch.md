---
description: saw watch — one unattended pass that ends running code the tool has identified, and remembers the rest.
---

# `saw watch`

Make one pass over what is running on this machine. It ends only code the tool has **identified**,
never asks for a password, and writes what it saw to its own record so a later pass can tell
something that has come back from something new.

```text
saw watch
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

## The record

The pass keeps a small record under your state directory of the code it has seen: when each was
first and last seen, how often, and whether it was ended. That is what lets it say *again* rather
than repeating the same alarm every pass.

The record holds no code — the payload itself is never written to it, because a command line can
carry your own secrets and that file outlives the run. Deleting the record costs nothing but the
history: the next pass still examines every process on its own evidence, so nothing can be hidden
from this command by editing or removing it.

## See also

- [`saw harden`](harden.md) — the same job with you present, and able to ask for privilege
- [`saw audit`](audit.md) — what else this machine looks like
