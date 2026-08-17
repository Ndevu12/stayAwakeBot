# Audit a machine

A repository scan says nothing about the machine it runs on. `saw audit` looks at the host: cached
credentials, editor settings, the start-up surface, and — with `--repo` — a repository's branch
protection. It is read-only, and it never cleans anything. Flags: [CLI
reference](../reference/cli.md#saw-audit).

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
using the machine further** — a delete leaves content recoverable, and continued use overwrites it.

## Credential findings

A token in your OS keychain is not automatically a problem, and deleting a credential path you
actually use is an outage, not a fix. These findings inform rather than instruct: read [credential
hygiene](../explanation/credential-hygiene.md) before acting on one.
