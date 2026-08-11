# Contributing to StayAwakeBot

Thanks for helping! StayAwakeBot is a distributable toolkit of **bots** (uptime +
security sentinels) over a shared `core`, packaged with `pyproject.toml`.

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests      # all tests must pass
```

**Python versions** — we support every maintained (non-EOL) CPython minor with real-world
deployment: currently **3.11–3.14**, tested in CI on each (the `ci.yml` matrix). The policy:
drop a version the release *after* it reaches upstream end-of-life, and add a new minor once it
ships — so the matrix evolves on its own. The packaged **floor** is `requires-python` in
`pyproject.toml`; keep the classifiers and the CI matrix in sync with it. The CI/dev toolchain
default lives in one place, [`.python-version`](.python-version) (read by `actions/setup-python`) —
bump it there, not in workflow files. (The `worm-scan` action stays pinned explicitly so it
remains self-contained for repos that adopt the gate.) The user-facing version requirement
lives in [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md).

## Pull requests
- Keep commits focused; describe **what** changed (not internal roadmap phases).
- Run the suite locally; the **Worm Guard** CI gate must pass (it blocks any infected/evil-merge change).
- For security-sensitive changes, see `prevent/SECURITY_BASELINE.md`.
