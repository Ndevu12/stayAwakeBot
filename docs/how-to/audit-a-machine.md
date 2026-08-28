---
description: Audit the developer machine itself: cached credentials, editor auto-run, the start-up surface, and whether rotating credentials is safe.
---

# Audit a machine

A repository scan says nothing about the machine it runs on. `saw audit` looks at the host: cached
credentials, editor settings, the start-up surface, and — with `--repo` — a repository's branch
protection. It is read-only, and it never cleans anything. Host denials are
[`saw harden`](harden-this-machine.md). Flags: [CLI
reference](../reference/cli/audit.md).

```bash
saw audit                       # hygiene + start-up surface + rotation verdict
saw audit --repo owner/name -f  # also gate on that repository's branch protection
saw audit --verify              # content-scan a suspicious directory the audit flagged
```

## Read the result

The report ends with a rotation-safety verdict.

| Result | Do this |
| --- | --- |
| Nothing found, and rotating credentials from this host is safe. | Nothing. |
| A weaker hygiene warning, and you passed `-f`. | Read it; act if it applies to you. |
| **Rotation unsafe** — either something is running at start-up that should not be, or the start-up surface could not be established. | Below. |

Rotation-unsafe gates whether or not you passed `-f`, because rotating a credential on a compromised host hands
the new one straight to whatever is running there.

## On a rotation-unsafe result

Work in this order, and rotate **last**:

1. **Isolate** the machine from the network.
2. **Neutralise** what the report names.
3. **Rebuild** if you cannot account for it. A host is never auto-cleaned.
4. **Rotate** credentials — from a machine you trust, not this one.

The verdict is also withheld when the start-up surface could not be established at all. A fresh
account, a container and a destroyed home directory look identical from disk, so `saw` reports the
ambiguity rather than picking one. If files you expect to be there are gone, **image the disk before
using the machine further**, `saw fix` included. How much survives depends on which wipe variant
ran, which cannot be told from the host — and every write can overwrite whatever did.

## On a "Not checked" section

Your machine did not let some checks finish — a tool they need is missing, or a path they read is
not readable by you. Each one names what stopped it.

Fix what it names and re-run, or inspect that surface yourself. Until you do, read the rest of the
report as covering everything **except** those surfaces. If one of them reads the start-up surface,
treat rotation as unsafe until you have checked it by hand.

## Credential findings

A token in your OS keychain is not automatically a problem, and deleting a credential path you
actually use is an outage, not a fix. These findings inform rather than instruct: read [credential
hygiene](../explanation/credential-hygiene.md) before acting on one.

### What a clean audit does and does not mean

`saw audit` reads this machine's start-up surface and the code it finds running. Use
`saw audit --verify` to look harder at what it flags; it is much slower.

**A clean audit is not a clean bill of health.** It covers this machine, at this moment, over the
surfaces this build examines — not your images, not your registries, not the accounts your machine
is enrolled in, and not whether an installed file is the one its publisher released. Where a check
could not run, a location it needed could not be read, or a surface is not covered on your
platform, the run says so and treats credential rotation as unsafe rather than reporting a clean
machine.

Three results not to over-read:

- **A green `saw guard` in CI says nothing about this machine.** `guard` gates a repository; run
  `saw audit` on the machine itself.
- **A clean editor result covers settings only.** An application's own code is checked separately;
  neither result stands in for the other.
- **A clean result over an application's own code is not proof the application is untouched.** Treat
  it as one signal among several.
