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

## Layout (one responsibility per folder)
```
src/stayawake/
  core/            shared utilities (io, timeutil, config, git) + adapters/
  bots/health/     uptime sentinel  (checker · reporter · alerter · service · cli/)
  bots/security/   security sentinel (scanner · matchers/ · targets/ · remediator · pr · data/ · cli/)
tests/             mirrors src (tests/bots/health, tests/bots/security)
config/            deployment config (urls.yml, security.yml)
```

## Principles we hold to
- **SRP** — one job per module/folder; new detection techniques are one file in `security/matchers/`.
- **DRY** — reuse `stayawake.core` (+ `core.adapters`); don't duplicate git/github/slack/io.
- **Data over code** — new worm indicators go in `src/stayawake/bots/security/data/signatures.yml`, not Python.
- **Tests mirror source** and must pass; add a test with every change.

## Adding a bot
1. Create `src/stayawake/bots/<bot>/` with `models`/`service` + a thin `cli/`.
2. Reuse `stayawake.core`; add console scripts in `pyproject.toml` (`stayawake-<bot>-<action>`).
3. Mirror tests under `tests/bots/<bot>/`. Existing bots stay untouched.

## Adding a worm signature (security bot)
Append an entry to `data/signatures.yml` with `id · category · severity · matcher · description`
and pick an existing `matcher` (content/filename/structural-json/heuristic/git-history). No code change needed.

## Pull requests
- Keep commits focused; describe **what** changed (not internal roadmap phases).
- Run the suite locally; the **Worm Guard** CI gate must pass (it blocks any infected/evil-merge change).
- For security-sensitive changes, see `docs/SECURITY_ARCHITECTURE.md` and `prevent/SECURITY_BASELINE.md`.
