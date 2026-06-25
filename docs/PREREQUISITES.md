# Prerequisites

## Python

You need **Python 3.11 or newer**. The package is built and tested against 3.11, 3.12, 3.13,
and 3.14, and there's no upper limit — newer releases keep working as they ship.

If `pip install stayawakebot` ends with:

```
ERROR: Could not find a version that satisfies the requirement stayawakebot (from versions: none)
ERROR: No matching distribution found for stayawakebot
```

it almost always means your Python is older than 3.11 — pip reports a version mismatch this way
rather than saying so directly. Install a 3.11+ interpreter (your distribution's `python3.12`
package, or `pyenv install 3.12`) and try again.

## Install

```bash
pip install stayawakebot          # or: pipx install stayawakebot
```

The console scripts and configuration are described in [USAGE.md](USAGE.md).

## Running without a local Python

A prebuilt image is published to GHCR, so Docker alone is enough:

```bash
docker run --rm ghcr.io/ndevu12/stayawakebot:latest saw scan --help
```
