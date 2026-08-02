---
name: saw-overview
description: Read first when working on StayAwakeBot / the `saw` CLI. What the tool is, its command surface, and the trust/threat model every change must respect (allowlist never trusts a scanned repo's own config; scan is read-only; fix is PR-only; heuristics are never auto-fixed; offline by default).
---

# saw / StayAwakeBot — overview & trust model

`saw` (package `stayawake`) is a distributable **supply-chain worm scanner + sentinel**: it detects,
reports, remediates, and *prevents* self-propagating package worms, plus does dependency-CVE auditing
and local hygiene. `docs/CLI.md` is the authoritative command reference; this skill is the mental model.

## Non-negotiable trust & safety invariants

- **Offline and fully accurate by ZERO flags.** A default `saw scan` needs no network and no config.
  The *only* thing that leaves the sandbox is `-x/--external` (spawns installed auditors). Never add a
  runtime dependency or a network call to the default path; vendor comparators instead.
- **The allowlist is operator-owned, never target-owned.** Suppressions come from ONE
  operator-chosen config per run (CWD-relative `config/security.yml` by default) — `saw` NEVER trusts a
  scanned repo's own config (that's an evasion vector). Consequence: `saw scan ~` flags the saw repo
  itself INFECTED (correct — run in-repo with its committed allowlist to clean). Allowlist rules MUST
  be signature-scoped; a bare `path_glob` with no `signature` is ignored (it would blanket-hide a fresh
  payload dropped under that path).
- **`scan` is read-only; `fix` writes only via a PR.** `scan`'s exit code *is* the verdict
  (0 clean / 1 infected / 2 errored-fail-closed), unconditionally — a CI gate just reads it.
  `saw fix` prepares a local branch and only publishes with `--pr`. Remediation NEVER lives in `scan`.
- **Heuristic/SUSPECT findings are never auto-fixed**, and a compromised *host* is never "auto-cleaned"
  (that would be a lie + a wiper hazard) — see `security-change-discipline`.
- **Fail closed.** A target that could not be fully scanned (unreadable file, failed clone, malformed
  config) must never read as clean — it exits non-zero. Warn loudly; never fail silently.

## Command surface (see docs/CLI.md for detail)

`scan` (read-only hunt) · `fix` (PR-only remediation) · `discard` · `audit` (+ `--verify` content-scans
a non-repo suspect dir; + credential/dependency hygiene) · `db` (offline advisory corpus) · `guard`
(install/verify the CI gate) · `search` · `intro` · `doctor` · `completion`.

Scan scope is **local by default** (given paths / configured globs / current repo); `--remote`
(or `--user`/`--org`) switches to GitHub repos. One scope per run. The scan CLI is repo-oriented
(0 repos → fail closed); default `exclude_dirs` hide `node_modules`/`dist`/`build`/`.next` (build
outputs where minification == obfuscation → all FPs), but a normal scan still emits an **honest
coverage note** when it didn't content-scan vendored code, and `--deep` opt-in does the confirmed-tier
full sweep. Large scans show a bounded dashboard + a written full-report file; the pager is opt-in
(`--pager`), never default.

## Related skills

`saw-architecture` (layers), `engineering-standard`, `working-with-this-codebase`, `shipping-changes`,
`security-change-discipline`, `scanner-performance`, `security-hardening-patterns`.
