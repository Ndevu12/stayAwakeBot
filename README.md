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

> **Prerequisites:** Python 3.11+ — see [Your first scan](docs/tutorial/first-scan.md).

```bash
pip install stayawakebot
```

Or the latest from source:
```bash
pip install "stayawakebot @ git+https://github.com/Ndevu12/stayAwakeBot@main"
```

Then hunt. Each of these stands alone:

**Scan the repository you are in:**

```bash
saw scan
```

**Or sweep every repository under a path:**

```bash
saw scan ~/dev
```

**Scan with your own allowlist**, rather than the packaged defaults:

```bash
saw scan --config config/security.yml
```

**Check the machine itself**, not a repository — credential hygiene and start-up entries:

```bash
saw audit
```

New here? `saw intro` is a 60-second tour, and `saw search "…"` finds the command you want.

> The distribution is published as **`stayawakebot`**; the security CLI is the terse **`saw`**
> command (see the [CLI reference](docs/reference/cli/index.md)).

## Don't hand-maintain that workflow

**Gate any repository's CI with one command — no install, no clone.**

Every repository you own should refuse an infected merge. `saw guard` writes that GitHub Actions
workflow, keeps it pinned, and proves it is enforced — for one repository or a whole organisation.
Each command below stands alone; reach for the one you need.

**Set it up.** Writes the gate here, for you to review and commit:

```bash
saw guard setup
```

**Or raise it as a pull request** instead, which never pushes to `main`:

```bash
saw guard setup --pr
```

**Check that a repository is actually guarded** — present, SHA-pinned, current, and *required*:

```bash
saw guard check
```

**Check a whole organisation**, failing if any repository lacks a required gate:

```bash
saw guard check --org your-org -f
```

`saw guard setup` *surgically pin-bumps* a gate that already exists rather than replacing it, and
never clobbers a workflow installed by some other means. `saw guard check` goes further than "is the
file there" — it verifies branch protection actually **requires** the check, because a gate that is
not required is decoration.

Both sweep many repositories at once (`--remote` / `--user` / `--org`), like `saw scan` and
`saw fix`. See the [CLI reference](docs/reference/cli/guard.md).

### The workflow, by hand

A minimal equivalent, if you would rather write it yourself than run `saw guard setup`. The
installed file is not identical — it also carries a weekly `pin-drift` job and prefers a
`GH_SECURITY_TOKEN` secret — so run `saw guard setup --dry-run` to see exactly what it would write:

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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1   # v7.0.1
        with:
          fetch-depth: 0        # full history is required

      - uses: Ndevu12/strix@93fe465d7b0266c6010778999b73b591ae082f3e      # v0.1.4
        with:
          version: '0.6.0'      # pin the scanner too; blank tracks latest
          # On an infected verdict, open ONE rolling `security/auto-clean` PR.
          # The gate still goes RED until that PR is merged — remediation opens
          # the fix, it does not make the check pass. Omit for detection only.
          remediate: pr
```

### About the pins

`Ndevu12/strix` ("StayAwakeBot Strix") is the public Action — a thin wrapper that installs the
published `stayawakebot` scanner from PyPI.

**Pin every action by commit SHA**, including this one: a tag can be moved to point at different code
after you have reviewed it, a SHA cannot. The trailing comment records which release the SHA
corresponds to, so the pin stays readable. In production pin `version:` as well — it selects the
`stayawakebot` release from PyPI and otherwise tracks whatever is latest at run time.

Other inputs: `config-file` to supply your own allowlist, `fail-on` to choose the verdict that fails
the build (default `infected`), and `upload-sarif` to send findings to code scanning.
See [Harden a repository](docs/how-to/harden-a-repo.md).

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
[Configuration](docs/reference/configuration.md#the-uptime-monitor-configurlsyml).

```bash
stayawake-health-check --config config/urls.yml
```

## Documentation

**[saw.ndevuspace.com](https://saw.ndevuspace.com)** — the full documentation, searchable and versioned.

- [Documentation index](docs/index.md) — everything below, in one place
- [Your first scan](docs/tutorial/first-scan.md) — install, scan, read the verdict, act
- [Gate a repository](docs/tutorial/gate-a-repo.md) — from unguarded to a required check
- [CLI reference](docs/reference/cli/index.md) — every command and flag, documented once
- [Configuration](docs/reference/configuration.md) · [exit codes](docs/reference/exit-codes.md) · [advisory DB](docs/reference/advisory-db.md)
- [Trust model](docs/explanation/trust-model.md) · [verdicts](docs/explanation/verdicts.md) · [fail closed](docs/explanation/fail-closed.md) · [safety envelope](docs/explanation/safety-envelope.md)
- [Credential hygiene](docs/explanation/credential-hygiene.md) — what a cached-credential finding means, and how to act on one safely
- [Harden a repository](docs/how-to/harden-a-repo.md) — the layered baseline for any repo
- [Contributing](CONTRIBUTING.md) — development setup and guidelines
- [Support](SUPPORT.md) — where to ask a question, file a bug, or report a false positive
- [Security policy](SECURITY.md) — how to report a security issue privately
- [Code of conduct](CODE_OF_CONDUCT.md) — what taking part here commits you to

## License

stayAwakeBot is **dual-licensed**:

- **[AGPL-3.0-or-later](LICENSE)** — free and open source. You must preserve attribution, and if you
  modify it and convey it or offer it over a network (e.g. as a hosted service), you must release
  your corresponding source under the AGPL too.
- **[Commercial license](COMMERCIAL-LICENSE.md)** — a paid, proprietary-use option for closed-source
  or proprietary-SaaS use without the AGPL's source-disclosure obligations. For terms, contact
  **saw@ndevuspace.com**.

