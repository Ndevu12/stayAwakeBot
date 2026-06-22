# StayAwakeBot — Architecture

Feature-first layout: each subtask (availability, security) is a self-contained
feature that shares a common core and external adapters. Layering runs
`cli → service → (domain + adapters) → common`. Every folder has one responsibility.

```
stayawakebot/
  common/        io · timeutil · config · git              # shared, pure (DRY)
  adapters/      http_client · github_api · slack · badge   # external I/O, one integration per file (SRP)
  availability/  models · config · checker · reporter · alerter · service   # health-check feature
  security/      models · signatures · scanner · service
                 matchers/  base · content · filename · structural · heuristic · git_history  # one technique per file
                 targets/   base · local · remote
  cli/           check · report · alert · security_scan     # thin: argparse → service
config/   urls.yml · security.yml · security_signatures.yml
tests/    common/ · availability/ · security/               # mirrors source
docs/     ARCHITECTURE.md · SECURITY_ARCHITECTURE.md
```

## Principles
- **SRP** — one responsibility per folder/file; matchers and targets are folders, one concern each.
- **DRY** — `common/` + `adapters/` are shared by every feature; no duplicated git/github/slack/io.
- **Reusability** — adapters, matchers, and targets are drop-in; CLIs are trivial wrappers.
- **Maintainability** — clear layering, typed domain models, tests mirror the tree.
- **Scalability** — a new subtask is added as a peer feature folder; new detections are added as
  data (`config/security_signatures.yml`) or a new file in `matchers/`.

## Entrypoints (used by `.github/workflows/`)
```
python -m stayawakebot.cli.check   --config config/urls.yml
python -m stayawakebot.cli.report
python -m stayawakebot.cli.alert
python -m stayawakebot.cli.security_scan --config config/security.yml
```

## Adding a feature
Create `stayawakebot/<feature>/` with its `models/service`, reuse `common/` + `adapters/`,
add a thin `cli/<entry>.py`, and mirror tests under `tests/<feature>/`. No existing feature changes.
