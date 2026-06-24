<!-- STAYAWAKEBOT_BADGE -->
![Health](https://img.shields.io/badge/health-0%2F2%20up-red)
<!-- STAYAWAKEBOT_BADGE_END -->
<!-- STAYAWAKEBOT_SECURITY_BADGE -->
![Security](https://img.shields.io/badge/security-29%20findings-red)
<!-- STAYAWAKEBOT_SECURITY_BADGE_END -->

# StayAwakeBot

StayAwakeBot is a distributable (`pip install`-able) Python monitoring **and** security
toolkit. Under one `stayawake` namespace it ships two bots over a shared `core`:

- **Health sentinel** — a URL/uptime availability monitor (HTTP status, latency, TLS,
  keyword checks) that writes JSON/markdown reports and a status badge.
- **Security sentinel** — a supply-chain worm hunter that detects, alerts on, and
  auto-fixes self-propagating malware (obfuscated loaders, fake fonts, VS Code auto-run
  tasks, and stealth "evil merges"), opening remediation PRs and gating CI.

Run either bot as a **console script** locally, or as **GitHub Actions** workflows that
commit reports back to the repository — the same packaged code in both places.

## Architecture

![StayAwakeBot architecture](public/stayawakebot_architecture.svg)

## Quick start

```bash
pip install stayawakebot                                            # from PyPI (released versions)
# or the latest from source:
pip install "stayawakebot @ git+https://github.com/Ndevu12/stayAwakeBot@main"
stayawake-health-check  --config config/urls.yml                    # uptime check
stayawake-security-scan --config config/security.yml --local-only   # worm scan
```

> The distribution is published as **`stayawakebot`** (the name `stayawake` is taken on
> PyPI by an unrelated project); the import package and `stayawake-*` commands are unchanged.

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
      - uses: Ndevu12/stayAwakeBot@v1      # pin to a SHA in production
        with:
          fail-on-findings: 'true'
```

Pin `@<sha>` rather than `@v1` for tamper-evident runs. See [Security baseline](prevent/SECURITY_BASELINE.md).

## Run via Docker (no local Python 3.14 needed)

Prefer not to install a 3.14 toolchain? Pull the image and scan a mounted repo:

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/ndevu12/stayawakebot \
  stayawake-security-scan --local-only --fail-on-findings
```

Tags: `:latest`, `:X.Y.Z`, `:X.Y`, and `:sha-<commit>`. The image runs as a non-root user, is
built from the same wheel published to PyPI, and ships SLSA provenance + SBOM attestations.

## Documentation

- [Usage](docs/USAGE.md) — install, run both bots, secrets, GitHub Actions, deploy your own
- [Configuration & Reports](docs/CONFIGURATION.md) — config file fields and report formats
- [Architecture](docs/ARCHITECTURE.md) — package layout and design principles
- [Security architecture](docs/SECURITY_ARCHITECTURE.md) — detection, remediation, prevention
- [Security baseline](prevent/SECURITY_BASELINE.md) — hardening checklist for any repo
- [Releasing](docs/RELEASING.md) — maintainer runbook: tags, PyPI Trusted Publishing, verification
- [Contributing](CONTRIBUTING.md) — development setup and guidelines

## License

MIT — see [LICENSE](LICENSE).
