# StayAwakeBot — Configuration & Reports

## `config/urls.yml` (health bot)

```yaml
settings:            # global defaults
  timeout_seconds: 10
  retries: 1
  user_agent: StayAwakeBot
  alert_on_failure: true
  alert_on_recovery: true
  consecutive_failures_before_alert: 1
urls:
  - name: Example
    url: https://example.com
    expected_status: 200
    max_response_ms: 2000
    check_ssl: true
    keyword: Example Domain
    tags: [public]
    timeout_seconds: 5      # per-URL override
```

**`settings`** (global defaults)
- `timeout_seconds` (int) — request timeout in seconds
- `retries` (int) — number of retries on failure
- `user_agent` (string) — User-Agent header
- `alert_on_failure` (bool) — enable failure alerts
- `alert_on_recovery` (bool) — enable recovery alerts
- `consecutive_failures_before_alert` (int) — require this many consecutive failures before alerting
- `reports_dir` (string, optional) — where reports are written (default `reports`); also settable per run with `--reports-dir`

**`urls`** (list of URLs to check)
- `name` (required) — friendly name
- `url` (required) — full URL to check
- `expected_status` (int) — expected HTTP status (e.g. 200)
- `max_response_ms` (int | null) — latency threshold in milliseconds
- `check_ssl` (bool) — inspect the TLS certificate (https only)
- `keyword` (string) — fail if this substring is absent from the body (case-insensitive)
- `tags` (list[string]) — grouping tags
- `timeout_seconds` (int) — per-URL override of the global timeout

## `config/security.yml` (security bot)

Targets (local globs + GitHub users/orgs), `exclude_dirs`, `max_file_bytes`,
`remote_clone_depth`, `reports_dir` (output location; default `reports/security`),
allowlist, and alert routing. The signature database ships **inside the package**; point
at a custom DB with `settings.signatures_path`. Full field reference and the layered
design live in [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md).

Each `allowlist` entry **must name a `signature`** (optionally scoped by `path_glob`) — a
bare `path_glob` is ignored so it can't blanket-suppress a fresh payload on that path:

```yaml
allowlist:
  - signature: fake-font-fa-solid-400
    path_glob: "tests/**"
```

## Reports

Reports are written under `reports/` and committed back to the repo.

| File | Contents |
|------|----------|
| `reports/latest.json` | latest raw results (`summary` block + `any_unhealthy`) |
| `reports/history.json` | append-only history of run summaries |
| `reports/status.json` | machine-readable current status |
| `reports/YYYY-MM-DD/HH-MM-UTC.md` | human-readable per-run markdown report |
| `reports/security/latest.{json,md}` | latest security scan results |

The checker writes `latest.json` and appends to `history.json`; the **reporter** produces
`status.json`, the dated markdown report, and the badge. (The checker does not write per-run
JSON files.)
