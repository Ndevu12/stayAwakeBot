<h1 align="center">StayAwakeBot</h1>

<p align="center">
  <strong>Supply-chain worm hunting for developer machines and CI.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/stayawakebot/"><img alt="PyPI" src="https://img.shields.io/pypi/v/stayawakebot"></a>
  <a href="https://pypi.org/project/stayawakebot/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/stayawakebot"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0--or--later%20%7C%20commercial-blue"></a>
</p>

---

A single compromised dependency is how one package becomes an organisation-wide incident.
Self-propagating packages spread through installs, builds and merges — arriving with code you
asked for, and running before you ever read it.

**`saw` hunts them where they land**: in your repositories, your lockfiles, your installed
dependency tree, and your machine's start-up surface. It then remediates through a pull request
and gates CI, so an infected change cannot merge.

**Offline and accurate with zero flags.** A default scan needs no network and no configuration.
`saw scan`'s exit code *is* the verdict, so a CI gate is one line.

| | |
| --- | --- |
| **Detect** | `saw scan` — repositories, lockfiles and installed dependency trees. Read-only, always. |
| **Remediate** | `saw fix` — prepares a cleanup branch per infected repo, `--pr` to publish. Never rewrites history; `saw discard` undoes it. |
| **Prevent** | `saw guard` — install and verify the CI gate on any repo. `saw hook` — scan on clone and pull, *before* you install or build. |
| **Audit** | `saw audit` — host hygiene and branch-protection posture, stating plainly what it did **not** examine. |
| **Advisories** | `saw db` — an offline corpus for dependency CVE and malicious-package matching. |

## Quick start

> **Prerequisites:** Python 3.11+ — see [docs/PREREQUISITES.md](docs/PREREQUISITES.md).

```bash
pip install stayawakebot
```

Or the latest from source:
```bash
pip install "stayawakebot @ git+https://github.com/Ndevu12/stayAwakeBot@main"
```

Then hunt:

```bash
saw scan                                     # the current repository
saw scan ~/dev                               # every repository under a path
saw scan --config config/security.yml        # with an operator-chosen allowlist
saw audit                                    # this machine's hygiene posture
```

New here? `saw intro` is a 60-second tour, and `saw search "…"` finds the command you want.

> The distribution is published as **`stayawakebot`**; the security CLI is the terse **`saw`**
> command (see the [CLI guide](docs/CLI.md)).

## Gate any repo's CI (GitHub Action)

Add the gate to any repository — no install, no clone. This is a working setup, not a sketch:

```yaml
# .github/workflows/worm-scan.yml
name: Worm scan

on:
  push:
    branches: [main]
  pull_request:

# Auto-remediation needs write access:
#   contents: write       -> push the security/auto-clean fix branch
#   pull-requests: write  -> open/update the rolling cleanup PR
# The scan itself only needs read; these are for the remediate step. Drop them
# both to `read` if you want detection without remediation.
permissions:
  contents: write
  pull-requests: write

jobs:
  strix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0   # v7.0.0
        with:
          fetch-depth: 0        # full history is required

      - uses: Ndevu12/strix@93fe465d7b0266c6010778999b73b591ae082f3e      # v0.1.4
        with:
          # On an infected verdict, open ONE rolling `security/auto-clean` PR.
          # The gate still goes RED until that PR is merged — remediation opens
          # the fix, it does not make the check pass. Omit for detection only.
          remediate: pr
```

`Ndevu12/strix` ("StayAwakeBot Strix") is the public Action — a thin wrapper that installs the
published `stayawakebot` scanner from PyPI.

**Pin every action by commit SHA, including this one.** A tag can be moved to point at different
code after you have reviewed it; a SHA cannot. The trailing comment records which release the SHA
corresponds to, so the pin stays readable.

In production also pin what the Action installs — `version:` selects the `stayawakebot` release from
PyPI and defaults to the latest. Other inputs: `config-file` to supply your own allowlist, `fail-on`
to choose the verdict that fails the build (default `infected`), and `upload-sarif` to send findings
to code scanning. `saw guard setup` writes and pin-bumps this workflow for you, and `saw guard check`
verifies a repo's gate is present, SHA-pinned, current, and required by branch protection.

See [Security baseline](prevent/SECURITY_BASELINE.md).

**Don't hand-maintain that workflow — let `saw` manage it.** [`saw guard setup`](docs/CLI.md#saw-guard)
writes (or *surgically pin-bumps*) exactly this gate for you — locally to review + commit, or
`--pr` to open a rolling PR — and [`saw guard check`](docs/CLI.md#saw-guard) verifies a repo's gate is
present, **SHA-pinned**, current, and **required** by branch protection. Both sweep many repos at once
(local by default, or `--remote`/`--user`/`--org`), just like `saw scan`/`saw fix`:

```bash
saw guard check                       # is this repo's gate present + SHA-pinned + current?
saw guard setup --pr                  # install/bump the gate → one rolling PR (never pushes main)
saw guard check --org your-org -f     # CI gate: fail if any repo lacks a required gate
```

## Run via Docker (no local Python needed)

Prefer not to install a Python toolchain at all? Pull the image and scan a mounted repo:

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/ndevu12/stayawakebot \
  saw scan /repo
```

The exit code is the verdict (`0` clean, `1` findings). To keep the report file too, mount a
writable dir and run as your own user so the bind-mount is writable:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/repo" \
  ghcr.io/ndevu12/stayawakebot \
  saw scan /repo --reports-dir /repo/reports
```

Tags: `:latest`, `:X.Y.Z`, `:X.Y`, and `:sha-<commit>`. The image runs as a non-root user, is
built from the same wheel published to PyPI, and ships SLSA provenance + SBOM attestations.

## Also in the package

`stayawakebot` additionally ships a **health sentinel** — a URL/uptime availability monitor
(HTTP status, latency, TLS and keyword checks) run with `stayawake-health-check`. It is
independent of `saw` and shares only the packaging. See
[Usage](docs/USAGE.md) and [Configuration](docs/CONFIGURATION.md).

```bash
stayawake-health-check --config config/urls.yml
```

## Documentation

- [CLI command guide](docs/CLI.md) — the `saw` security commands (scan, fix, audit, guard, …)
- [Usage](docs/USAGE.md) — install, run both bots, secrets, GitHub Actions, deploy your own
- [Configuration & Reports](docs/CONFIGURATION.md) — config file fields and report formats
- [Prerequisites](docs/PREREQUISITES.md) — supported Python versions and install troubleshooting
- [Security baseline](prevent/SECURITY_BASELINE.md) — hardening checklist for any repo
- [Contributing](CONTRIBUTING.md) — development setup and guidelines

## License

stayAwakeBot is **dual-licensed** (from v0.1.9 onward):

- **[AGPL-3.0-or-later](LICENSE)** — free and open source. You must preserve attribution, and if you
  modify it and convey it or offer it over a network (e.g. as a hosted service), you must release
  your corresponding source under the AGPL too.
- **[Commercial license](COMMERCIAL-LICENSE.md)** — a paid, proprietary-use option for closed-source
  or proprietary-SaaS use without the AGPL's source-disclosure obligations. Contact the author for terms.

Releases up to and including v0.1.8 were published under the MIT license and remain MIT for those versions.

