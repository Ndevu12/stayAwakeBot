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
  consecutive_healthy_before_recovery: 1   # recovery debounce (defaults to the failure threshold)
  alert_repo: "owner/name"                 # where the status issue lives — required to file one
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
- `consecutive_healthy_before_recovery` (int, optional) — require this many consecutive healthy checks before declaring recovery (debounces flapping endpoints; defaults to `consecutive_failures_before_alert`)
- `alert_repo` (string) — `owner/name` of the repository the status issue is kept in. **No default, on purpose:** an uptime alert names the endpoints it monitors and carries their outage history, so it is never filed into whatever repository happens to host the workflow. Unset ⇒ no issue is filed (the run says so and continues).

### GitHub issue alerting (health bot)

The sentinel keeps **one self-updating issue per project** (label `stayawakebot-sentinel`), found by a stable hidden marker in the body rather than the title. While a project is down the issue body is **refreshed silently** (edits don't notify); a comment is posted **only on state transitions** — the first DOWN (issue opened) and recovery (one comment, then the issue is **closed**). The body names the *failing dimension* (status / latency / keyword / TLS) and carries a collapsed incident log of recent transitions, so the tracker shows only active incidents instead of one issue per run.

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

Targets (local globs + GitHub users/orgs), scan `settings`, allowlist, and alert routing. The
signature database ships **inside the package**; point at a custom DB with
`settings.signatures_path`. The layered design and the detection rules themselves are maintained
privately.

**`settings`** — every key is optional, and each has a CLI equivalent that wins when both are given:

| Key | Default | Effect |
|-----|---------|--------|
| `exclude_dirs` | `.git`, `node_modules`, `.next`, `dist`, `build`, `.malware-quarantine`, `.venv` | Directories never traversed. Keep it minimal: every name here is a place a committed payload could hide from a CI gate that scans with this file. |
| `max_file_bytes` | `2000000` | Read cap for content matching. A larger *source* file is still scanned head+tail; only non-source assets are skipped. |
| `remote_clone_depth` | `50` | Shallow-clone depth for `--remote` targets (the history matchers need several commits). |
| `scan_build_outputs` | `false` | Un-prune `dist`/`build`/`out`/`.next` and run the self-evident construct checks there. Noisier by design; emits heuristic (SUSPICIOUS) findings only. |
| `deep` | `false` | Content-scan installed dependency code, as `saw scan --deep`. |
| `dependency_advisories` | `true` | The offline CVE-advisory section. `saw scan --no-advisories` turns it off for one run. Advisories never affect the verdict or exit code. |
| `external_audit` | `false` | Run installed external auditors, as `saw scan -x`. **The one setting that leaves the offline sandbox.** |
| `require_db` | `false` | Fail (exit 2) when the advisory DB is missing or fails its integrity check, instead of degrading to the inline seed. As `saw scan --require-db`. |
| `jobs` | auto | Worker count; an int, or `auto`/empty for automatic. Below 1 is clamped to 1; an unparseable value falls back to automatic rather than failing the scan. `-j/--jobs` wins. |
| `parallel_min_files` | `256` | File-count floor below which a single target is scanned sequentially (a pool is not worth its startup cost on a small repo). |
| `reports_dir` | — | Intended fallback location for the report bundle. **Currently inert for `saw scan`** ([#1454](https://github.com/Ndevu12/stayAwakeBot/issues/1454)): the bundle is only written when `-d/--reports-dir DIR` is passed, and that `DIR` then takes precedence over this. Pass `-d` with the path you want. |
| `signatures_path` | packaged DB | Path to a custom signature database. |

Booleans are parsed strictly, so a quoted `external_audit: "false"` reads as **false** rather than
being coerced true — a security-sensitive setting can never be enabled by quoting.

`targets.local` is **optional**: for ad-hoc local scans you can pass paths on the command
line (`saw scan <path>…` / `--path`), and a bare `saw scan` with nothing configured scans
the current repository. A token is never needed for local
scanning — see [USAGE.md](USAGE.md#ad-hoc-local-scanning-no-token-no-config).

Each `allowlist` entry **must name a `signature`** (optionally scoped by `path_glob`) — a
bare `path_glob` is ignored so it can't blanket-suppress a fresh payload on that path:

```yaml
allowlist:
  - signature: fake-font-fa-solid-400
    path_glob: "tests/**"
```

## Reports

**Neither bot writes a report into your repository, and nothing is committed back.**

The **health bot** writes no files at all: `stayawake-health-check` probes the URLs, refreshes its
single GitHub status issue (`settings.alert_repo`), and posts to Slack on a state transition.

The **security bot** is terminal-first — `saw scan` renders the full report to `stdout` and
persists nothing by default. Durable output is opt-in, one sink per flag:

| Sink | Flag | Evidence | Destination |
|------|------|----------|-------------|
| Terminal | (default) | full | `stdout` (ephemeral) |
| JSON | `--json` | full | `stdout` (pipe it; no file) |
| SARIF | `--sarif FILE` | redacted | `FILE`, for GitHub code-scanning |
| Alert | `--alert` | evidence-free | GitHub issue + Slack |
| Reports dir | `-d DIR` | redacted | `DIR/latest.{json,md}` (default `reports/security`, or `settings.reports_dir`) |

Redacted means a persisted artifact stores a `{sha256, preview, len}` fingerprint in place of the
raw match, so a security report on disk can never re-distribute a live payload. See
[CLI.md](CLI.md#how-reports-are-stored-evidence--redaction).
