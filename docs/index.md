---
description: Documentation for saw — a supply-chain worm hunter. Install it, run your first scan, harden the host, gate CI, and look up any command.
---

# StayAwakeBot documentation

`saw` hunts supply-chain worms in repositories, lockfiles, installed packages and on the host.
The fix opens as a pull request. The host is hardened; the merge is gated. The last line of the
report is the verdict.

For developers who ship software — in any of the eight package ecosystems `saw`
[reads](reference/advisory-db.md#ecosystems-saw-reads) — and for the people who keep an
organisation's repositories gated. The vector is the same whatever the stack: a dependency
install, a build, or an editor or agent opening the folder.

**Start here** — [Your first scan](tutorial/first-scan.md) ·
[Gate a repository](tutorial/gate-a-repo.md)

**Do a task** — [scan local code](how-to/scan-local.md) ·
[scan GitHub repositories](how-to/scan-remote.md) · [fix findings](how-to/fix-findings.md) ·
[gate CI](how-to/gate-ci.md) · [scan on clone](how-to/scan-on-clone.md) ·
[audit a machine](how-to/audit-a-machine.md) · [harden this machine](how-to/harden-this-machine.md) ·
[harden a repository](how-to/harden-a-repo.md)

**Look it up** — [CLI reference](reference/cli/index.md) ·
[configuration](reference/configuration.md) · [advisory database](reference/advisory-db.md)

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
