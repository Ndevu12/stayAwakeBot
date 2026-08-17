# Configuration

Both files are optional. Local scanning needs neither — pass paths on the command line, or stand in a
repository. Every CLI flag mentioned here is described in the [CLI reference](cli/index.md).

## The scanner (`config/security.yml`)

Targets (local globs and GitHub users/orgs), scan `settings`, the allowlist, and alert routing. The
signature database ships inside the package.

Every `settings` key is optional, and the CLI equivalent wins when both are given:

| Key | Default | Effect |
| --- | --- | --- |
| `exclude_dirs` | `.git`, `node_modules`, `.next`, `dist`, `build`, `.malware-quarantine`, `.venv` | Directories never traversed. Keep the list minimal. |
| `max_file_bytes` | `2000000` | Read cap for content matching. A larger *source* file is still scanned head and tail. |
| `remote_clone_depth` | `50` | Clone depth for `--remote` targets. |
| `scan_build_outputs` | `false` | Also examine `dist`/`build`/`out`/`.next`. Noisier by design; heuristic findings only. |
| `deep` | `false` | As `saw scan --deep`. |
| `dependency_advisories` | `true` | The offline CVE-advisory section. Advisories never affect the verdict or exit code. |
| `external_audit` | `false` | As `saw scan -x`. **The one setting that leaves the offline sandbox.** |
| `require_db` | `false` | As `saw scan --require-db`. |
| `jobs` | auto | Worker count; an int, or `auto`. An unparseable value falls back to automatic rather than failing the scan. `-j` wins. |
| `parallel_min_files` | `256` | File count below which a single target is scanned sequentially. |
| `reports_dir` | — | Where a report bundle is written. Setting it **is** the opt-in — no `-d` needed. Precedence: `-d` → `STAYAWAKE_REPORTS_DIR` → this. With none of the three set, a scan writes nothing. |
| `signatures_path` | packaged | Path to a custom signature database. |

Booleans are parsed strictly, so `external_audit: "false"` reads as false rather than being coerced
true — a security-sensitive setting can never be switched on by quoting.

Each `allowlist` entry **must name a `signature`**, optionally narrowed by `path_glob`. A bare
`path_glob` is ignored, so it cannot blanket-suppress whatever lands on that path next:

```yaml
allowlist:
  - signature: fake-font-fa-solid-400
    path_glob: "tests/**"
```

The allowlist is yours, not the scanned repository's — see [trust
model](../explanation/trust-model.md).

## The uptime monitor (`config/urls.yml`)

`stayawake-health-check` is an availability monitor that ships in the same package and is otherwise
unrelated to `saw`. It writes no files and commits nothing: it probes each URL, refreshes one
self-updating GitHub issue per project, and posts to Slack on a state change.

```bash
stayawake-health-check --config config/urls.yml
stayawake-health-check --config config/urls.yml --fail-on-unhealthy   # exit non-zero when down
```

```yaml
settings:
  timeout_seconds: 10
  retries: 1
  user_agent: StayAwakeBot
  alert_on_failure: true
  alert_on_recovery: true
  consecutive_failures_before_alert: 1
  consecutive_healthy_before_recovery: 1
  alert_repo: "owner/name"
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

**`settings`** — `timeout_seconds`, `retries` and `user_agent` shape the request;
`alert_on_failure` / `alert_on_recovery` switch alerting; `consecutive_failures_before_alert` and
`consecutive_healthy_before_recovery` debounce a flapping endpoint (recovery defaults to the failure
threshold). `alert_repo` is the `owner/name` where the status issue lives — **no default, on
purpose**: an uptime alert names the endpoints it monitors, so it is never filed into whatever
repository happens to host the workflow. Unset means no issue is filed, and the run says so.

**`urls`** — `name` and `url` are required. `expected_status`, `max_response_ms`, `check_ssl` and
`keyword` (a case-insensitive substring that must be present) each define a failing dimension, which
the alert names. `tags` group endpoints and `timeout_seconds` overrides the global timeout.

To run it on your own repositories: fork, put your URLs in `config/urls.yml`, add
`SLACK_WEBHOOK_URL` as a repository secret if you want Slack, and push — the bundled workflow runs on
a schedule and whenever that file changes.

## Reports

Neither tool writes a report into your repository, and nothing is committed back. `saw scan` renders
to the terminal and persists nothing by default; durable output is one opt-in sink per flag — see
[report sinks](cli/sinks.md).
