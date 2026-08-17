---
description: saw hunts self-propagating supply-chain malware in repositories, lockfiles and installed dependencies — offline, read-only, and remediating only through a pull request.
---

# StayAwakeBot documentation

`saw` hunts self-propagating supply-chain malware in your repositories, lockfiles, installed
dependency trees and your machine's start-up surface. It remediates through a pull request and gates
CI, so an infected change cannot merge. A default scan is offline, needs no configuration, and its
exit code is the verdict.

For developers who run `npm install`, editor auto-tasks and agent tooling, and for the people who
keep an organisation's repositories gated.

**Start here** — [Your first scan](tutorial/first-scan.md) ·
[Gate a repository](tutorial/gate-a-repo.md)

**Do a task** — [scan local code](how-to/scan-local.md) ·
[scan GitHub repositories](how-to/scan-remote.md) · [fix findings](how-to/fix-findings.md) ·
[gate CI](how-to/gate-ci.md) · [scan on clone](how-to/scan-on-clone.md) ·
[audit a machine](how-to/audit-a-machine.md) · [harden a repository](how-to/harden-a-repo.md)

**Look it up** — [CLI reference](reference/cli/index.md) ·
[configuration](reference/configuration.md) · [exit codes](reference/exit-codes.md) ·
[advisory database](reference/advisory-db.md)

**What the tool promises** — [trust model](explanation/trust-model.md) ·
[verdicts](explanation/verdicts.md) · [fail closed](explanation/fail-closed.md) ·
[safety envelope](explanation/safety-envelope.md) ·
[credential hygiene](explanation/credential-hygiene.md)

The package also ships an unrelated uptime monitor, `stayawake-health-check` — see
[configuration](reference/configuration.md#the-uptime-monitor-configurlsyml).

## Which version you are reading

Each release keeps its own copy of these pages, and the version selector at the top switches
between them. `latest` follows the current documentation.

Documented versions begin at **0.6.2**. Earlier releases were published before this site existed,
so there are no pages describing them — rather than reprinting today's documentation under an older
number, which would describe behaviour those versions do not have. If you are running something
earlier, `saw --version` and `saw <command> -h` describe the copy you actually have.
