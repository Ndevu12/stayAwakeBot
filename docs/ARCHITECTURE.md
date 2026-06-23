# StayAwakeBot — Architecture

Two bots as **separate top-level packages** (`health`, `security`) over a shared core
(`shared`). Each bot is self-contained; layering runs
`cli → service → (domain + adapters) → shared`. Every folder has one responsibility.

```
shared/        io · timeutil · config · git           # shared utilities (DRY)
  adapters/    http_client · github_api · slack · badge   # external I/O, one integration per file (SRP)
health/        models · config · checker · reporter · alerter · service   # uptime sentinel bot
  cli/         check · report · alert                 # thin: argparse → service
security/      models · signatures · scanner · service · reporter · alerter · remediator · pr
  matchers/    base · content · filename · structural · heuristic · git_history  # one technique per file
  targets/     base · local · remote
  cli/         scan · report · alert · remediate
config/   urls.yml · security.yml · security_signatures.yml
tests/    health · security                     # mirrors source (run with `-t .`)
docs/     ARCHITECTURE.md · SECURITY_ARCHITECTURE.md
```

## Principles
- **SRP** — one responsibility per folder/file; matchers and targets are folders, one concern each.
- **DRY** — `shared/` (+ `shared/adapters/`) is reused by both bots; no duplicated git/github/slack/io.
- **Reusability** — adapters, matchers, and targets are drop-in; CLIs are trivial wrappers.
- **Maintainability** — clear layering, typed domain models, tests mirror the tree.
- **Scalability** — a new bot is added as another top-level package; new detections are added as
  data (`config/security_signatures.yml`) or a new file in `security/matchers/`.

## Entrypoints (used by `.github/workflows/`)
```
python -m health.cli.check   --config config/urls.yml
python -m health.cli.report
python -m health.cli.alert
python -m security.cli.scan --config config/security.yml
python -m security.cli.remediate [--apply] [--open-pr] [--remote]
```

## Adding a bot
Create a new top-level package `<bot>/` with its `models`/`service` + a thin `cli/`,
reuse `shared/` (+ `shared/adapters/`), and mirror tests under `tests/<bot>/`. The
existing bots are untouched.
EOF
