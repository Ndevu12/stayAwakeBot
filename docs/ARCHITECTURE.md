# StayAwakeBot — Architecture

A distributable (`pip install`-able) toolkit: two bots as packages under one
`stayawake` namespace, over a shared `core`. Layering runs
`cli → service → (domain + adapters) → core`. One responsibility per folder.

```
src/stayawake/                     ← single import root (installable; no name clashes)
  core/        io · timeutil · config · git          # shared utilities (DRY)
    adapters/  http_client · github_api · slack · badge   # external I/O, one per file (SRP)
  bots/
    health/    models · config · checker · reporter · alerter · service · cli/   # uptime sentinel
    security/  models · signatures · scanner · service · reporter · alerter · remediator · pr
      matchers/  base · content · filename · structural · heuristic · git_history  # one technique/file
      targets/   base · local · remote
      data/      signatures.yml      # default IoC DB shipped INSIDE the package
      cli/       scan · report · alert · remediate
pyproject.toml   packaging: metadata · console scripts · package-data
config/   urls.yml · security.yml        # deployment config (targets/allowlist; signatures are packaged)
tests/    bots/health · bots/security    # mirrors src
docs/  prevent/  reports/  .github/  CONTRIBUTING.md
```

## Principles
- **SRP** — `core` (utilities) · `bots/*` (each bot) · `cli/` (entrypoints) · `data/` (signatures) are separate.
- **DRY** — `core` (+ `core/adapters`) is reused by both bots; console scripts reuse the thin `main()`s; one packaged signature source.
- **Reusability / distributability** — `pip install stayawakebot` gives a self-contained scanner with console commands; the worm-scan Action installs it instead of cloning.
- **Maintainability / collaboration** — standard modern `src/` layout, `pyproject.toml` single source of truth, `CONTRIBUTING.md`, tests mirror `src`, importable without path tricks.
- **Scalability** — a new bot is `src/stayawake/bots/<bot>/`; new shared code is `src/stayawake/core/<x>`; new detections are data (`…/security/data/signatures.yml`) or a file in `security/matchers/`.

## Install & run
```bash
pip install -e .            # or: pip install .
stayawake-health-check   --config config/urls.yml
stayawake-health-report
stayawake-health-alert
stayawake-security-scan  --config config/security.yml
stayawake-security-remediate [--apply] [--open-pr] [--remote]
python -m unittest discover -s tests      # tests (package must be installed)
```
(`python -m stayawake.bots.<bot>.cli.<action>` works too.)

## Adding a bot
Create `src/stayawake/bots/<bot>/` with its `models`/`service` + a thin `cli/`,
reuse `stayawake.core` (+ `core.adapters`), register console scripts in `pyproject.toml`,
and mirror tests under `tests/bots/<bot>/`. Existing bots are untouched.
