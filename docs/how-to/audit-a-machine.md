---
description: Audit the developer machine itself: cached credentials, editor auto-run, the start-up surface, and whether rotating credentials is safe.
---

# Audit a machine

A repository scan says nothing about the machine it runs on. `saw audit` looks at the host: cached
credentials, editor settings, the start-up surface, and — with `--repo` — a repository's branch
protection. It is read-only, and it never cleans anything. Flags: [CLI
reference](../reference/cli/audit.md).

```bash
saw audit                       # hygiene + start-up surface + rotation verdict
saw audit --repo owner/name -f  # also gate on that repository's branch protection
saw audit --verify              # content-scan a suspicious directory the audit flagged
saw audit; echo $?
```

## Read the result

| Exit | Meaning | Do this |
| --- | --- | --- |
| `0` | Nothing found, and rotating credentials from this host is safe. | Nothing. |
| `1` | A weaker hygiene warning, and you passed `-f`. | Read it; act if it applies to you. |
| `3` | **Rotation unsafe** — either something is running at start-up that should not be, or the start-up surface could not be established. | Below. |

`3` gates whether or not you passed `-f`, because rotating a credential on a compromised host hands
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

## Credential findings

A token in your OS keychain is not automatically a problem, and deleting a credential path you
actually use is an outage, not a fix. These findings inform rather than instruct: read [credential
hygiene](../explanation/credential-hygiene.md) before acting on one.

### What `saw audit` does not scan

`saw audit` reads the host persistence surface, a targeted set of known drop-paths — your home
directory, `/tmp`, the system temp dir, the working directory — and the JavaScript that installed
applications load. Use `saw audit --verify` to look harder at what it flags; it is much slower.

**It does not scan** — so a clean audit is not a clean bill of health for any of these:

| not scanned | why it matters |
| --- | --- |
| other survivor temp dirs | a payload staged where `$TMPDIR` does not point survives a reboot |
| the global npm prefix, beyond Node's own resolution paths | a globally installed package is not read |
| Docker images and volumes | a compromised image is untouched by a host scan |
| other mounted filesystems | only the paths above are walked |
| account and organization state | a self-hosted runner registered against the org survives a host rebuild |
| Windows autorun | registry Run keys, the Startup folder and Scheduled Tasks are enumerated nowhere — persistence enumeration is macOS and Linux user-scope only |
| an application shipped as a packed archive | only unpacked application trees are read |
| editor and browser extensions | enumerated nowhere |
| whether a file is what its publisher shipped | nothing is compared against a published copy |

Three results not to over-read:

- **A green `saw guard` in CI says nothing about this machine.** `guard` gates a repository; run
  `saw audit` on the machine itself.
- **A clean editor result covers settings only.** An application's own JavaScript is checked
  separately; neither result stands in for the other.
- **A clean result over an application's own JavaScript is not proof the application is untouched.**
  Treat it as one signal among several.
