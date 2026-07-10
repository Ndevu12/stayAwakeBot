# StayAwakeBot

StayAwakeBot is a distributable (`pip install`-able) Python monitoring **and** security
toolkit. Under one `stayawake` namespace it ships two bots over a shared `core`:

- **Health sentinel** — a URL/uptime availability monitor (HTTP status, latency, TLS,
  keyword checks) that writes JSON/markdown reports.
- **Security sentinel** — a supply-chain worm hunter that detects, alerts on, and
  auto-fixes self-propagating malware (obfuscated loaders, fake fonts, VS Code auto-run
  tasks, and stealth "evil merges"), opening remediation PRs and gating CI.

Run either bot as a **console script** locally, or as **GitHub Actions** workflows that
commit reports back to the repository — the same packaged code in both places.

## Architecture

Coming soon

## Quick start

> **Prerequisites:** Python 3.11+ — see [docs/PREREQUISITES.md](docs/PREREQUISITES.md).

```bash
pip install stayawakebot                                            # from PyPI (released versions)
```

Or the latest from source:
```bash
pip install "stayawakebot @ git+https://github.com/Ndevu12/stayAwakeBot@main"
```

Health check

```bash
stayawake-health-check  --config config/urls.yml      
```

Uptime check (remote-only bot)

```bash
saw scan --config config/security.yml --local                       # worm scan (local security CLI)
```

> The distribution is published as **`stayawakebot`**. Local security runs through the terse **`saw`** command (see the
> [CLI guide](docs/CLI.md)).

## Gate any repo's CI (GitHub Action)

Add the security sentinel to any repository in one step — no install, no clone:

```yaml
# .github/workflows/worm-guard.yml
on: [pull_request, push]
jobs:
  worm-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # full history so evil merges are detectable
      - uses: Ndevu12/strix@v1             # pin to a SHA in production
        with:
          fail-on-findings: 'true'
```

`Ndevu12/strix` ("StayAwakeBot Strix") is the public Action — a thin wrapper that installs the
published `stayawakebot` scanner from PyPI. Pin `@<sha>` rather than `@v1` for tamper-evident
runs. See [Security baseline](prevent/SECURITY_BASELINE.md).

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

> Note: that provenance attests **`saw`'s own** build. When `saw` *scans* a target it is purely
> behavioral — it never treats a scanned package's SLSA / PEP-740 / sigstore attestation as a trust
> signal (Shai-Hulud 2.0 shipped valid provenance). See
> [SECURITY_ARCHITECTURE.md → Provenance is not trust](docs/SECURITY_ARCHITECTURE.md#provenance-is-not-trust-and-the-build-artifact-blind-spot).

## Documentation

- [CLI command guide](docs/CLI.md) — the `saw` security commands (scan, run, fix, audit, …)
- [Usage](docs/USAGE.md) — install, run both bots, secrets, GitHub Actions, deploy your own
- [Configuration & Reports](docs/CONFIGURATION.md) — config file fields and report formats
- [Architecture](docs/ARCHITECTURE.md) — package layout and design principles
- [Security architecture](docs/SECURITY_ARCHITECTURE.md) — detection, remediation, prevention
- [Security baseline](prevent/SECURITY_BASELINE.md) — hardening checklist for any repo
- [Releasing](docs/RELEASING.md) — maintainer runbook: tags, PyPI Trusted Publishing, verification
- [Contributing](CONTRIBUTING.md) — development setup and guidelines

## License

stayAwakeBot is **dual-licensed** (from v0.1.9 onward):

- **[AGPL-3.0-or-later](LICENSE)** — free and open source. You must preserve attribution, and if you
  modify it and convey it or offer it over a network (e.g. as a hosted service), you must release
  your corresponding source under the AGPL too.
- **[Commercial license](COMMERCIAL-LICENSE.md)** — a paid, proprietary-use option for closed-source
  or proprietary-SaaS use without the AGPL's source-disclosure obligations. Contact the author for terms.

Releases up to and including v0.1.8 were published under the MIT license and remain MIT for those versions.

