# Trust model

What `saw` trusts, and what it refuses to.

## Accurate with zero flags

A default `saw scan` needs no network, no configuration and no credential. Accuracy is not something
you unlock by passing options; the defaults are the supported way to run it. That matters because the
machine you most need to scan is often the one you least want to hand a token to.

## Only one flag leaves the sandbox

`-x/--external` runs auditors you already have installed and folds their results in; such a tool may
send your dependency list to its own servers. It is opt-in for exactly that reason, and it never
changes the verdict. Everything else runs against local data. `--remote` is not an exception: it
clones the repositories you asked for and scans them the same way.

## The allowlist is yours, never the target's

Suppressions come from **one operator-chosen config per run**. `saw` never reads suppression input
from the repository it is scanning, so a repository cannot ship an allowlist that excuses its own
payload — the [scan-on-clone hook](../how-to/scan-on-clone.md) bakes in *your* config precisely so a
fresh clone cannot supply one. An allowlist entry must name a signature; a bare path pattern is
ignored rather than silently suppressing whatever appears there next.

## A credential is used for the minimum, and never handled loosely

Local scanning uses no credential at all. Where one is needed it reaches git through `GIT_ASKPASS`,
never through a URL or process arguments, so it cannot leak through `ps`, git's error output or a CI
log. `saw audit` reports on credentials without ever reading a live secret's bytes. See
[credentials](../reference/cli/credentials.md).

## Evidence stays where you put it

Full match evidence exists on your terminal and in `--json`. Anything written to disk carries a
fingerprint instead, so a report can never re-distribute a live payload, and an alert body carries no
evidence at all.

## What is not published

How detection decides — the signals, the thresholds, the corroboration — is deliberately not
documented publicly. Published detection mechanics are an evasion aid. If you are evaluating `saw`,
the promises on these pages are the contract; the internals are not part of it.
