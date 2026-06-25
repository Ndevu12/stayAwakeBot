# Prerequisites

The single source of truth for what you need to install and run StayAwakeBot. Other docs link
here instead of repeating it.

## Python

StayAwakeBot is a pure-Python package supporting **Python 3.11–3.14**, tested on each in CI.
Installation requires **Python ≥ 3.11** — there is **no upper bound**, so newer interpreters
(3.14 and future releases) install and run fine even before they're added to the test matrix.

On an interpreter older than 3.11, `pip install stayawakebot` fails with:

```
ERROR: Could not find a version that satisfies the requirement stayawakebot (from versions: none)
ERROR: No matching distribution found for stayawakebot
```

That is pip's (cryptic) way of saying your interpreter is below the floor — not that the package
is missing. Switch to 3.11+: use your distro's `python3.12` package, or
`pyenv install 3.12 && pyenv local 3.12`.

## Install

```bash
pip install stayawakebot          # or: pipx install stayawakebot
```

See [USAGE.md](USAGE.md) for the console scripts and configuration.

## No local Python? Use the container

The same tool ships as a digest-pinned, non-root image on GHCR, so Docker is the only
requirement:

```bash
docker run --rm ghcr.io/ndevu12/stayawakebot:latest stayawake-security-scan --help
```
