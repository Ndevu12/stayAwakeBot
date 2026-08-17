# Credential hygiene

A cached GitHub credential is not automatically a vulnerability, and `saw audit`'s credential
findings deliberately **inform rather than instruct** — deleting a credential path you actually use
is an outage, not a fix. What matters is a credential's lifetime, its scope, and whether a process
running as you can copy it.

The full reasoning, and the verified way to remove one without locking yourself out, is
**[docs/CREDENTIAL_HYGIENE.md](../CREDENTIAL_HYGIENE.md)**. It stays at that path because every
credential finding links to it by URL.

Acting on a finding: [audit a machine](../how-to/audit-a-machine.md).
